"""Jenkins Pipeline connector (read-only). Built against a real Jenkins (2.580.1) running one
pipeline per masking pattern (tests/contract/jenkins/, tests/fixtures/jenkins-real/).

Mapping:
  project  = job path, e.g. "team/app/main" (folders and multibranch: /job/team/job/app/job/main)
  pipeline = build number                     GET {job}/{n}/api/json
  jobs     = stages, with their hierarchy     GET {job}/{n}/stages/tree      (Pipeline Graph View)
             e.g. "Scan / Matrix - LANG = 'go' / sast"; fallback: wfapi (Stage View), flat names
  masking  = step nodes                       GET {job}/{n}/stages/allSteps
  reports  = archived artifacts               GET {job}/{n}/artifact/{relativePath}

Jenkins specifics, each handled explicitly (all seen on the real Jenkins):
  * catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') leaves the build SUCCESS with the
    stage failed; warnError / unstable make the stage UNSTABLE. Both are failures the build was
    allowed to survive (allow_failure).
  * A scripted try/catch leaves the stage SUCCESS; its failed step node is the only trace. A
    failed step followed by a successful run of the same step (retry) is a retry, not a mask.
  * If step nodes can't be read (plugin missing, no permission), masking is reported unknown.
  * Auth is HTTP Basic user:API-token (Jenkins has no bearer tokens), only to the Jenkins origin.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from scanproof.connectors.base import AuthError, ConnectorError, ErrorKind, NotFoundError
from scanproof.connectors.http import DEFAULT_MAX_ARTIFACT_BYTES, HttpConnector
from scanproof.models import Job, JobStatus, Pipeline

STAGE_SEPARATOR = " / "
_SEGMENT = re.compile(r"^[^/\x00-\x1f]+$")

_BUILD_RESULT = {
    "SUCCESS": "success",
    "UNSTABLE": "unstable",
    "FAILURE": "failed",
    "ABORTED": "canceled",
    "NOT_BUILT": "skipped",
}
# Pipeline Graph View node states (lower case) and Stage View (wfapi) statuses
_STATE = {
    "success": JobStatus.SUCCESS,
    "failure": JobStatus.FAILED,
    "failed": JobStatus.FAILED,
    "unstable": JobStatus.FAILED,
    "aborted": JobStatus.CANCELED,
    "not_built": JobStatus.SKIPPED,
    "not_executed": JobStatus.SKIPPED,
    "skipped": JobStatus.SKIPPED,
    "running": JobStatus.RUNNING,
    "in_progress": JobStatus.RUNNING,
    "queued": JobStatus.PENDING,
    "paused": JobStatus.MANUAL,
    "paused_pending_input": JobStatus.MANUAL,
}


class JenkinsConnector(HttpConnector):
    provider = "jenkins"
    label = "Jenkins"
    auth_hint = "Set JENKINS_USER and JENKINS_TOKEN (an API token of a read-only user)."
    default_auth_scheme = "basic"

    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        username: str | None = None,
        anonymous: bool = False,
        timeout: float = 30.0,
        ca_bundle: str | None = None,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if token and not anonymous and not username:
            raise AuthError("Jenkins API tokens need a username (JENKINS_USER).")
        super().__init__(
            base_url,
            token,
            api_url=base_url,
            anonymous=anonymous,
            timeout=timeout,
            ca_bundle=ca_bundle,
            max_retries=max_retries,
            backoff_seconds=backoff_seconds,
            max_artifact_bytes=max_artifact_bytes,
            transport=transport,
            sleep=sleep,
            username=username,
        )
        self._builds: dict[tuple[str, int], dict[str, Any]] = {}

    # ------------------------------------------------------------------ public API

    def get_pipeline(self, project: str, pipeline_id: int) -> Pipeline:
        build = self._build(project, pipeline_id)
        try:
            result = build.get("result")
            status = "running" if build.get("building") else _BUILD_RESULT.get(result, "unknown")
            return Pipeline(
                id=int(build["number"]),
                sha=_commit(build) or "",
                ref=_branch(build),
                status=status,
                web_url=build.get("url"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Unexpected build: {exc}") from exc

    def list_jobs(self, project: str, pipeline_id: int) -> list[Job]:
        build = self._build(project, pipeline_id)
        base = f"{_job_path(project)}/{int(pipeline_id)}"
        build_result = build.get("result")
        sha = _commit(build)
        steps = self._steps(base)  # None: could not read step nodes
        try:
            tree = self._get_json_capped(f"{self.api_url}{base}/stages/tree", "stage graph")
            nodes = _flatten(tree["data"]["stages"])
        except NotFoundError:
            nodes = self._wfapi_nodes(base)
        except (KeyError, TypeError) as exc:
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, "Unexpected stage graph") from exc

        jobs = []
        for node_id, name, state, finished in nodes:
            status = _STATE.get(str(state).lower(), JobStatus.UNKNOWN)
            raw = str(state).lower()
            allow_failure = False
            masking_checked: bool | None = None
            if status is JobStatus.FAILED and build_result in ("SUCCESS", "UNSTABLE"):
                allow_failure = True
                how = "unstable (warnError / unstable)" if raw == "unstable" else "failed"
                raw = f"{how}, but the build continued ({build_result}; catchError / warnError)"
            elif status is JobStatus.SUCCESS:
                masking_checked = steps is not None
                masked = _swallowed_failure(steps.get(node_id, [])) if steps is not None else None
                if masked:
                    status, allow_failure = JobStatus.FAILED, True
                    raw = f"succeeded, but step '{masked}' failed and was caught (try/catch)"
            jobs.append(
                Job(
                    id=int(node_id),
                    name=name,
                    status=status,
                    raw_status=raw,
                    allow_failure=allow_failure,
                    masking_checked=masking_checked,
                    commit_sha=sha,
                    pipeline_id=int(pipeline_id),
                    finished_at=finished if status.is_terminal else None,
                )
            )
        return sorted(jobs, key=lambda j: j.id)

    def fetch_report(
        self, project: str, job: Job, report_path: str, artifact_name: str | None = None
    ) -> bytes:
        """Archived artifacts belong to the build (any stage could have archived them)."""
        build = self._build(project, job.pipeline_id or 0)
        wanted = _clean_path(report_path)
        archived = {a.get("relativePath") for a in build.get("artifacts") or []}
        if wanted not in archived:
            sample = ", ".join(sorted(p for p in archived if p)[:10]) or "(none)"
            raise NotFoundError(f"'{wanted}' was not archived (archived: {sample})", None)
        base = f"{_job_path(project)}/{int(job.pipeline_id or 0)}"
        url = f"{self.api_url}{base}/artifact/{quote(wanted)}"
        return self._download(url, f"artifact '{wanted}'")

    def run_matches(
        self, invocation_uri: str | None, pipeline: Pipeline, job_ids: set[int]
    ) -> bool | None:
        return None  # Sigstore's Fulcio has no Jenkins identity; attestations use same_run: false

    # ------------------------------------------------------------------ helpers

    def _raise_for_status(self, response: httpx.Response, what: str) -> None:
        self._raise_standard(response, what, "Check JENKINS_USER / JENKINS_TOKEN and job read.")

    def _build(self, project: str, number: int) -> dict[str, Any]:
        key = (project, int(number))
        if key not in self._builds:
            tree = (
                "number,result,building,url,"
                "artifacts[relativePath,fileName],"
                "actions[_class,lastBuiltRevision[SHA1,branch[name]],remoteUrls]"
            )
            url = f"{self.api_url}{_job_path(project)}/{int(number)}/api/json?tree={quote(tree)}"
            build = self._get_json_capped(url, f"build #{number}")
            if not isinstance(build, dict):
                raise ConnectorError(ErrorKind.INVALID_RESPONSE, "Build is not an object")
            self._builds[key] = build
        return self._builds[key]

    def _steps(self, base: str) -> dict[str, list[tuple[str, str]]] | None:
        """stage id -> [(step name, state)] in order; None if step nodes can't be read."""
        try:
            body = self._get_json_capped(f"{self.api_url}{base}/stages/allSteps", "step nodes")
            out: dict[str, list[tuple[str, str]]] = {}
            for step in body["data"]["steps"]:
                out.setdefault(str(step["stageId"]), []).append(
                    (str(step.get("title") or step.get("name")), str(step.get("state")).lower())
                )
            return out
        except NotFoundError:
            return self._wfapi_steps(base)
        except (ConnectorError, KeyError, TypeError):
            return None

    def _wfapi_nodes(self, base: str) -> list[Node]:
        """Stage View fallback: no hierarchy, so nested stages keep their own names."""
        body = self._get_json_capped(f"{self.api_url}{base}/wfapi/describe", "stages (wfapi)")
        try:
            return [
                (
                    str(s["id"]),
                    str(s["name"]),
                    str(s["status"]),
                    _finished_at(s.get("startTimeMillis"), s.get("durationMillis")),
                )
                for s in body["stages"]
            ]
        except (KeyError, TypeError) as exc:
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, "Unexpected wfapi stages") from exc

    def _wfapi_steps(self, base: str) -> dict[str, list[tuple[str, str]]] | None:
        try:
            out: dict[str, list[tuple[str, str]]] = {}
            for node_id, _, _, _ in self._wfapi_nodes(base):
                url = f"{self.api_url}{base}/execution/node/{quote(node_id)}/wfapi/describe"
                stage = self._get_json_capped(url, "stage nodes (wfapi)")
                out[node_id] = [
                    (
                        f"{n.get('name')}: {n.get('parameterDescription') or ''}",
                        str(n.get("status")).lower(),
                    )
                    for n in stage.get("stageFlowNodes", [])
                ]
            return out
        except (ConnectorError, KeyError, TypeError, AttributeError):
            return None


Node = tuple[str, str, str, datetime | None]  # id, qualified name, state, finished at


def _flatten(stages: list[dict[str, Any]], prefix: str = "") -> list[Node]:
    out: list[Node] = []
    for node in stages:
        name = f"{prefix}{node['name']}"
        finished = _finished_at(node.get("startTimeMillis"), node.get("totalDurationMillis"))
        out.append((str(node["id"]), name, str(node.get("state")), finished))
        out += _flatten(node.get("children") or [], f"{name}{STAGE_SEPARATOR}")
    return out


def _finished_at(start: Any, duration: Any) -> datetime | None:
    """Stage end from start + duration (ms); None unless both are sane integers."""
    if isinstance(start, int) and isinstance(duration, int) and start > 0 and duration >= 0:
        return datetime.fromtimestamp((start + duration) / 1000, UTC)
    return None


def _swallowed_failure(steps: list[tuple[str, str]]) -> str | None:
    """A failed step that no later successful run of the same step made good."""
    for i, (name, state) in enumerate(steps):
        if state in ("failure", "failed"):
            retried = any(n == name and s == "success" for n, s in steps[i + 1 :])
            if not retried:
                return name
    return None


def _commit(build: dict[str, Any]) -> str | None:
    """SHA of the first git checkout recorded on the build (the Jenkinsfile's repository)."""
    for action in build.get("actions") or []:
        if isinstance(action, dict) and "BuildData" in str(action.get("_class", "")):
            sha = (action.get("lastBuiltRevision") or {}).get("SHA1")
            if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha):
                return sha
    return None


def _branch(build: dict[str, Any]) -> str | None:
    for action in build.get("actions") or []:
        if isinstance(action, dict) and "BuildData" in str(action.get("_class", "")):
            branches = (action.get("lastBuiltRevision") or {}).get("branch") or []
            if branches and isinstance(branches[0], dict):
                name = branches[0].get("name")
                return name.removeprefix("refs/remotes/origin/") if name else None
    return None


def _job_path(project: str) -> str:
    segments = [s for s in str(project).strip("/").split("/") if s]
    if not segments or any(s in (".", "..") or not _SEGMENT.match(s) for s in segments):
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Bad Jenkins job path {project!r}")
    return "".join(f"/job/{quote(s, safe='')}" for s in segments)


def _clean_path(report_path: str) -> str:
    wanted = report_path.strip().lstrip("/")
    while wanted.startswith("./"):
        wanted = wanted[2:]
    if ".." in wanted.split("/"):
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, "Report path must not contain '..'")
    return wanted
