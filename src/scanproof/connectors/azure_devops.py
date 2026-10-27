"""Azure DevOps Pipelines connector (read-only). Built against real responses from public
projects (dnceng-public/public, azure-sdk/public; tests/fixtures/azure-real/).

Mapping:
  project  = "<organization>/<project>" (Azure DevOps Server: "<collection>/<project>")
  pipeline = build                GET {org}/{project}/_apis/build/builds/{id}
  jobs     = timeline Job records GET .../builds/{id}/timeline, named "<stage> / <job>"
  reports  = build artifact       GET .../builds/{id}/artifacts?artifactName=..&$format=zip

Azure specifics, each handled explicitly (all seen in real builds):
  * A task that fails under `continueOnError: true` makes the task AND its job
    `succeededWithIssues`, and the build `partiallySucceeded`. That job is reported as a failure
    the pipeline was allowed to survive. (Tasks that only log warnings can also end
    `succeededWithIssues`; a scan job with issues is not a clean success either.)
  * Every artifact records the timeline record (job) that published it, so a report is accepted
    only from an artifact the required job published itself (stronger than GitHub).
  * Re-run jobs: the timeline holds the latest attempt; earlier attempts are read from the
    timelines listed in `previousAttempts`.
  * Artifact zips are requested from the API origin. Build artifacts (PublishBuildArtifacts) are
    served from it directly. Pipeline Artifacts redirect to artifacts.visualstudio.com with no
    signed URL; the token is not sent there, so a private project's Pipeline Artifact is
    reported as unavailable (UNKNOWN), with that explanation. PATs go as Basic (empty user),
    System.AccessToken / Entra tokens as Bearer.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx

from scanproof.connectors.base import AuthError, ConnectorError, ErrorKind, NotFoundError
from scanproof.connectors.http import DEFAULT_MAX_ARTIFACT_BYTES, HttpConnector
from scanproof.models import Job, JobStatus, Pipeline

DEFAULT_AZURE_URL = "https://dev.azure.com"
API_VERSION = "7.1"
STAGE_SEPARATOR = " / "
MAX_PREVIOUS_TIMELINES = 20

_RESULT = {
    "succeeded": JobStatus.SUCCESS,
    "succeededWithIssues": JobStatus.FAILED,  # see module docstring
    "failed": JobStatus.FAILED,
    "canceled": JobStatus.CANCELED,
    "abandoned": JobStatus.CANCELED,
    "skipped": JobStatus.SKIPPED,
}
_STATE = {"pending": JobStatus.PENDING, "inProgress": JobStatus.RUNNING}


class AzureDevOpsConnector(HttpConnector):
    provider = "azure-devops"
    label = "Azure DevOps"
    auth_hint = (
        "Set AZURE_DEVOPS_TOKEN (a PAT with Build: Read, or $(System.AccessToken) in a pipeline)."
    )
    default_auth_scheme = "basic"  # PATs; pass auth_scheme="bearer" for OAuth / Entra tokens

    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        anonymous: bool = False,
        auth_scheme: str | None = None,
        timeout: float = 30.0,
        ca_bundle: str | None = None,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
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
            username="",
            auth_scheme=auth_scheme,  # type: ignore[arg-type]
        )

    # ------------------------------------------------------------------ public API

    def get_pipeline(self, project: str, pipeline_id: int) -> Pipeline:
        build = self._get(project, f"builds/{int(pipeline_id)}", f"build {pipeline_id}")
        try:
            status = build.get("result") or build.get("status") or "unknown"
            return Pipeline(
                id=int(build["id"]),
                sha=build.get("sourceVersion") or "",
                ref=_short_ref(build.get("sourceBranch")),
                status=status,
                source=build.get("reason"),
                created_at=build.get("queueTime"),
                finished_at=build.get("finishTime"),
                web_url=((build.get("_links") or {}).get("web") or {}).get("href"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Unexpected build: {exc}") from exc

    def list_jobs(self, project: str, pipeline_id: int) -> list[Job]:
        build = self._get(project, f"builds/{int(pipeline_id)}", f"build {pipeline_id}")
        sha = build.get("sourceVersion")
        timeline = self._get(project, f"builds/{int(pipeline_id)}/timeline", "timeline")
        records = _records(timeline)
        jobs = [self._to_job(r, records, sha, int(pipeline_id)) for r in records.values()]
        jobs = [j for j in jobs if j is not None]

        # earlier attempts of re-run jobs live in their own timelines
        wanted: dict[str, set[str]] = {}
        for r in records.values():
            if r.get("type") == "Job":
                for prev in r.get("previousAttempts") or []:
                    if isinstance(prev, dict) and prev.get("timelineId") and prev.get("recordId"):
                        wanted.setdefault(str(prev["timelineId"]), set()).add(str(prev["recordId"]))
        for timeline_id in list(wanted)[:MAX_PREVIOUS_TIMELINES]:
            path = f"builds/{int(pipeline_id)}/timeline/{quote(timeline_id, safe='')}"
            old = _records(self._get(project, path, "previous attempt timeline"))
            for record_id in wanted[timeline_id]:
                if record_id in old:
                    merged = {**records, **{k: v for k, v in old.items() if k not in records}}
                    job = self._to_job(old[record_id], merged, sha, int(pipeline_id))
                    if job is not None:
                        jobs.append(job)
        return sorted(jobs, key=lambda j: (j.name, j.attempt or 0))

    def fetch_report(
        self, project: str, job: Job, report_path: str, artifact_name: str | None = None
    ) -> bytes:
        if not artifact_name:
            raise ConnectorError(
                ErrorKind.INVALID_RESPONSE,
                "Azure DevOps artifacts are published per build: set artifact_name in the policy",
            )
        build_id = int(job.pipeline_id or 0)
        listing = self._get(project, f"builds/{build_id}/artifacts", "artifacts")
        matches = [
            a
            for a in (listing.get("value") or [])
            if isinstance(a, dict) and a.get("name") == artifact_name
        ]
        if not matches:
            raise NotFoundError(f"No artifact named '{artifact_name}' in build {build_id}", None)
        artifact = matches[0]
        source = artifact.get("source")
        if source and job.ref and str(source) != job.ref:
            raise NotFoundError(
                f"Artifact '{artifact_name}' was published by another job (timeline record "
                f"{source}), not by '{job.name}'",
                None,
            )
        url = (
            f"{self._project_url(project)}/_apis/build/builds/{build_id}/artifacts"
            f"?artifactName={quote(artifact_name)}&%24format=zip&api-version={API_VERSION}"
        )
        try:
            archive = self._download(url, f"artifact '{artifact_name}'")
        except AuthError as exc:
            if exc.status_code == 203 or self.anonymous:
                raise
            # Pipeline Artifacts (PublishPipelineArtifact) redirect to Microsoft's artifact host
            # without a signed URL. ScanProof sends the token only to the API origin.
            raise AuthError(
                f"{exc.message} If '{artifact_name}' is a Pipeline Artifact, Azure serves it from "
                "artifacts.visualstudio.com, where ScanProof does not send the token; publish "
                "the report with PublishBuildArtifacts instead (served by the API origin).",
                exc.status_code,
            ) from None
        try:
            return self._extract(
                archive, f"{artifact_name}/{report_path.lstrip('/')}", artifact_name
            )
        except NotFoundError:
            return self._extract(archive, report_path, artifact_name)

    # ------------------------------------------------------------------ helpers

    def _raise_for_status(self, response: httpx.Response, what: str) -> None:
        # Azure answers some auth failures with 203 + an HTML sign-in page.
        if response.status_code == 203:
            raise AuthError(f"Azure DevOps sent a sign-in page for {what}. {self.auth_hint}", 203)
        self._raise_standard(response, what, self.auth_hint)

    def _project_url(self, project: str) -> str:
        parts = [p for p in str(project).strip("/").split("/") if p]
        if len(parts) != 2 or any(p in (".", "..") for p in parts):
            raise ConnectorError(
                ErrorKind.INVALID_RESPONSE,
                f"Azure DevOps project must be '<organization>/<project>', got {project!r}",
            )
        return f"{self.api_url}/{quote(parts[0], safe='')}/{quote(parts[1], safe='')}"

    def _get(self, project: str, path: str, what: str) -> dict[str, Any]:
        url = f"{self._project_url(project)}/_apis/build/{path}?api-version={API_VERSION}"
        body = self._get_json_capped(url, what)
        if not isinstance(body, dict):
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Unexpected {what}")
        return body

    def _to_job(
        self, r: dict[str, Any], records: dict[str, dict[str, Any]], sha: str | None, build: int
    ) -> Job | None:
        if r.get("type") != "Job":
            return None
        try:
            state, result = r.get("state"), r.get("result")
            if state == "completed":
                status = _RESULT.get(str(result), JobStatus.UNKNOWN)
            else:
                status = _STATE.get(str(state), JobStatus.UNKNOWN)
            allow_failure = result == "succeededWithIssues"
            raw = str(result or state)
            if allow_failure:
                tasks = [
                    t.get("name")
                    for t in records.values()
                    if t.get("parentId") == r.get("id")
                    and t.get("result") in ("succeededWithIssues", "failed")
                ]
                raw = (
                    "succeededWithIssues: a task failed under continueOnError or reported "
                    f"issues ({', '.join(str(t) for t in tasks[:3]) or 'no task named'})"
                )
            return Job(
                id=_number(str(r["id"])),
                ref=str(r["id"]),
                name=_qualified_name(r, records),
                stage=_stage_name(r, records),
                status=status,
                raw_status=raw,
                allow_failure=allow_failure,
                commit_sha=sha,
                pipeline_id=build,
                started_at=r.get("startTime"),
                finished_at=r.get("finishTime"),
                attempt=r.get("attempt"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Unexpected record: {exc}") from exc


def _records(timeline: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = timeline.get("records")
    if not isinstance(records, list):
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, "Timeline has no records")
    return {str(r["id"]): r for r in records if isinstance(r, dict) and r.get("id")}


def _stage_name(r: dict[str, Any], records: dict[str, dict[str, Any]]) -> str | None:
    seen = 0
    node = records.get(str(r.get("parentId")))
    while node is not None and seen < 10:
        if node.get("type") == "Stage":
            name = node.get("name")
            return None if name in (None, "__default") else str(name)
        node = records.get(str(node.get("parentId")))
        seen += 1
    return None


def _qualified_name(r: dict[str, Any], records: dict[str, dict[str, Any]]) -> str:
    stage = _stage_name(r, records)
    name = str(r.get("name"))
    return f"{stage}{STAGE_SEPARATOR}{name}" if stage else name


def _number(guid: str) -> int:
    """Stable 53-bit number for a GUID (JSON-safe), used where ScanProof expects an int id."""
    try:
        return uuid.UUID(guid).int % (2**53)
    except ValueError:
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Bad record id {guid!r}") from None


def _short_ref(ref: str | None) -> str | None:
    if not ref:
        return None
    for prefix in ("refs/heads/", "refs/tags/"):
        if ref.startswith(prefix):
            return ref[len(prefix) :]
    return ref
