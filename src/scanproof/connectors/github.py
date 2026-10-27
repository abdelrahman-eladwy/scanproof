"""GitHub Actions connector (read-only). Built and tested against real responses from this
repository's own workflow runs (tests/fixtures/github-real/).

Mapping:
  pipeline = workflow run        GET /repos/{repo}/actions/runs/{run_id}
  jobs     = all attempts        GET /repos/{repo}/actions/runs/{run_id}/jobs?filter=all
  reports  = run artifact (zip)  GET /repos/{repo}/actions/runs/{run_id}/artifacts
                                 GET /repos/{repo}/actions/artifacts/{id}/zip

GitHub specifics, each handled explicitly:
  * Artifacts belong to the run, not to a job, so policies must name the artifact
    (`artifact_name`). ScanProof checks the zip against the artifact's recorded sha256 digest.
  * `continue-on-error` on a STEP leaves the step's and the job's conclusion at "success" in the
    REST API. The only trace is a failure-level check-run annotation ("Process completed with
    exit code N"), so successful jobs are cross-checked against their annotations. If the
    token can't read them (needs `checks: read`), the job's success is reported as unknown.
  * `continue-on-error` on a JOB shows the job as "failure" while the run succeeds; that
    combination is reported as a failure masked by continue-on-error.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import time
import zipfile
from collections.abc import Callable, Iterator
from typing import Any, ClassVar
from urllib.parse import quote

import httpx

from scanproof.connectors.base import AuthError, ConnectorError, ErrorKind, NotFoundError
from scanproof.connectors.http import (
    DEFAULT_MAX_ARTIFACT_BYTES,
    MAX_PAGES,
    HttpConnector,
    origin_of,
)
from scanproof.models import Job, JobStatus, Pipeline

DEFAULT_GITHUB_API = "https://api.github.com"
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_EXIT_CODE = re.compile(r"Process completed with exit code [1-9]\d*")
_RUN_URI = re.compile(
    r"^(?P<host>https://[^/]+)/(?P<repo>[^/]+/[^/]+)/actions/runs/(?P<run>\d+)(?:/attempts/\d+)?/?$"
)
MAX_ANNOTATION_PAGES = 20  # 2,000 annotations; beyond that masking is reported as unknown

_CONCLUSION = {
    "success": JobStatus.SUCCESS,
    "failure": JobStatus.FAILED,
    "timed_out": JobStatus.FAILED,
    "startup_failure": JobStatus.FAILED,
    "cancelled": JobStatus.CANCELED,
    "skipped": JobStatus.SKIPPED,
    "action_required": JobStatus.PENDING,
}
_IN_PROGRESS = {
    "queued": JobStatus.PENDING,
    "waiting": JobStatus.PENDING,
    "pending": JobStatus.PENDING,
    "requested": JobStatus.PENDING,
    "in_progress": JobStatus.RUNNING,
}


class GitHubConnector(HttpConnector):
    provider = "github"
    label = "GitHub"
    auth_hint = "Set GITHUB_TOKEN (needs actions:read and checks:read)."
    extra_headers: ClassVar[dict[str, str]] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    def __init__(
        self,
        api_url: str,
        token: str | None,
        *,
        anonymous: bool = False,
        timeout: float = 30.0,
        ca_bundle: str | None = None,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            api_url,
            token,
            api_url=api_url,
            anonymous=anonymous,
            timeout=timeout,
            ca_bundle=ca_bundle,
            max_retries=max_retries,
            backoff_seconds=backoff_seconds,
            max_artifact_bytes=max_artifact_bytes,
            transport=transport,
            sleep=sleep,
        )
        self._run_conclusion: dict[tuple[str, int], str | None] = {}

    # ------------------------------------------------------------------ public API

    def fetch_attestations(self, project: str, subject_digest: str) -> bytes:
        """GET /repos/{repo}/attestations/sha256:{hex}. Needs `attestations: read` for
        GITHUB_TOKEN. Pages are size-capped like artifacts; only inline bundles are used
        (bundle_url points at snappy-compressed blobs on another host)."""
        digest = subject_digest.lower().removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"not a sha256 digest: {digest!r}")
        path = f"/repos/{_repo(project)}/attestations/sha256:{digest}"
        url: str | None = f"{self.api_url}{path}"
        params: dict[str, Any] | None = {"per_page": 100}
        bundles: list[Any] = []
        for _ in range(MAX_PAGES):
            if url is None:
                break
            try:
                body, url = self._download_page(url, path, params)
            except NotFoundError:
                break  # no attestations for this digest
            params = None
            try:
                items = json.loads(body)["attestations"]
                if not isinstance(items, list):
                    raise TypeError("attestations is not a list")
            except (ValueError, KeyError, TypeError) as exc:
                raise ConnectorError(
                    ErrorKind.INVALID_RESPONSE, f"Unexpected attestations page from {path}"
                ) from exc
            bundles += [i["bundle"] for i in items if isinstance(i, dict) and i.get("bundle")]
        else:
            raise ConnectorError(ErrorKind.LIMIT_EXCEEDED, f"More than {MAX_PAGES} pages")
        return json.dumps({"attestations": [{"bundle": b} for b in bundles]}).encode()

    def run_matches(
        self, invocation_uri: str | None, pipeline: Pipeline, job_ids: set[int]
    ) -> bool | None:
        """https://<host>/<owner>/<repo>/actions/runs/<run_id>[/attempts/<n>]"""
        if not invocation_uri:
            return None
        m = _RUN_URI.match(invocation_uri)
        if not m:
            return None
        if pipeline.web_url:
            run = _RUN_URI.match(pipeline.web_url)
            if run and (run.group("host"), run.group("repo").lower()) != (
                m.group("host"),
                m.group("repo").lower(),
            ):
                return False
        return int(m.group("run")) == pipeline.id

    def get_pipeline(self, project: str, pipeline_id: int) -> Pipeline:
        run = self._get_json(f"/repos/{_repo(project)}/actions/runs/{int(pipeline_id)}")
        try:
            self._run_conclusion[(project, int(pipeline_id))] = run.get("conclusion")
            return Pipeline(
                id=run["id"],
                sha=run["head_sha"],
                ref=run.get("head_branch"),
                status=run.get("conclusion") or run["status"],
                source=run.get("event"),
                created_at=run.get("created_at"),
                finished_at=run.get("updated_at") if run.get("status") == "completed" else None,
                web_url=run.get("html_url"),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ConnectorError(
                ErrorKind.INVALID_RESPONSE, f"Unexpected run payload: {exc}"
            ) from exc

    def list_jobs(self, project: str, pipeline_id: int) -> list[Job]:
        key = (project, int(pipeline_id))
        if key not in self._run_conclusion:
            self.get_pipeline(project, pipeline_id)
        run_succeeded = self._run_conclusion.get(key) == "success"
        path = f"/repos/{_repo(project)}/actions/runs/{int(pipeline_id)}/jobs"
        jobs = [
            self._to_job(project, item, run_succeeded)
            for item in self._paginate(path, "jobs", {"filter": "all"})
        ]
        return sorted(jobs, key=lambda j: j.id)

    def fetch_report(
        self, project: str, job: Job, report_path: str, artifact_name: str | None = None
    ) -> bytes:
        if not artifact_name:
            raise ConnectorError(
                ErrorKind.INVALID_RESPONSE,
                "GitHub artifacts belong to the run, not a job: set artifact_name in the policy",
            )
        run_id = job.pipeline_id
        path = f"/repos/{_repo(project)}/actions/runs/{run_id}/artifacts"
        matches = [
            a
            for a in self._paginate(path, "artifacts", {"name": artifact_name})
            if a.get("name") == artifact_name
        ]
        if not matches:
            raise NotFoundError(f"No artifact named '{artifact_name}' in run {run_id}", None)
        artifact = max(matches, key=lambda a: a.get("id", 0))
        if artifact.get("expired"):
            raise NotFoundError(f"Artifact '{artifact_name}' has expired", None)

        archive = self._download(
            f"{self.api_url}/repos/{_repo(project)}/actions/artifacts/{artifact['id']}/zip",
            what=f"artifact '{artifact_name}'",
        )
        _verify_digest(archive, artifact.get("digest"), artifact_name)
        return self._extract(archive, report_path, artifact_name)

    # ------------------------------------------------------------------ helpers

    def _to_job(self, project: str, item: dict[str, Any], run_succeeded: bool) -> Job:
        try:
            status_raw = item.get("status")
            conclusion = item.get("conclusion")
            if status_raw == "completed":
                status = _CONCLUSION.get(conclusion or "", JobStatus.UNKNOWN)
            else:
                status = _IN_PROGRESS.get(status_raw or "", JobStatus.UNKNOWN)
            raw = conclusion or status_raw
            allow_failure = False
            masking_checked: bool | None = None

            if status is JobStatus.FAILED and run_succeeded:
                # A failed job inside a successful run: tolerated by job-level continue-on-error.
                allow_failure = True
                raw = f"{conclusion} (job continue-on-error; run succeeded)"
            elif status is JobStatus.SUCCESS:
                masked = self._masked_step_failure(item)
                masking_checked = masked is not None
                if masked:
                    status, allow_failure = JobStatus.FAILED, True
                    detail = masked.rstrip(".")
                    raw = f"succeeded, but a step failed under continue-on-error ({detail})"

            return Job(
                id=item["id"],
                name=item["name"],
                status=status,
                raw_status=raw,
                allow_failure=allow_failure,
                masking_checked=masking_checked,
                commit_sha=item.get("head_sha"),
                pipeline_id=item.get("run_id"),
                created_at=item.get("created_at"),
                started_at=item.get("started_at"),
                finished_at=item.get("completed_at"),
                web_url=item.get("html_url"),
                attempt=item.get("run_attempt"),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ConnectorError(
                ErrorKind.INVALID_RESPONSE, f"Unexpected job payload: {exc}"
            ) from exc

    def _masked_step_failure(self, item: dict[str, Any]) -> str | bool | None:
        """Return the failure message if a step failed silently, False if none did, None if the
        annotations could not all be read.

        Every page is read: a job with many annotations (e.g. linter warnings) can push the
        failure past the first page, which used to make a masked step look clean.
        """
        url = item.get("check_run_url")
        if not url or origin_of(url) != self._origin:
            return None
        next_url: str | None = f"{url}/annotations"
        params: dict[str, Any] | None = {"per_page": 100}
        for _ in range(MAX_ANNOTATION_PAGES):
            try:
                response = self._send(next_url, params)
                self._raise_for_status(response, "check run annotations")
                annotations = response.json()
            except (ConnectorError, ValueError):
                return None
            if not isinstance(annotations, list):
                return None
            for note in annotations:
                message = str(note.get("message", "")) if isinstance(note, dict) else ""
                if note.get("annotation_level") == "failure" and _EXIT_CODE.search(message):
                    return message.strip()
            next_url = response.links.get("next", {}).get("url")
            if not next_url:
                return False
            if origin_of(next_url) != self._origin:
                return None
            params = None  # the next link carries its own query
        return None  # too many pages to be sure: unknown, never "clean"

    def _extract(self, archive: bytes, report_path: str, artifact_name: str) -> bytes:
        wanted = report_path.strip().lstrip("/")
        while wanted.startswith("./"):
            wanted = wanted[2:]
        if ".." in wanted.split("/"):
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, "Report path must not contain '..'")
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                names = zf.namelist()
                if wanted not in names:
                    sample = ", ".join(names[:10]) or "(empty)"
                    raise NotFoundError(
                        f"'{wanted}' not found in artifact '{artifact_name}' (contains: {sample})",
                        None,
                    )
                info = zf.getinfo(wanted)
                if info.file_size > self.max_artifact_bytes:
                    raise ConnectorError(
                        ErrorKind.LIMIT_EXCEEDED,
                        f"'{wanted}' is {info.file_size} bytes; limit is {self.max_artifact_bytes}",
                    )
                out = bytearray()
                with zf.open(info) as fh:
                    while chunk := fh.read(65536):
                        out += chunk
                        # Defense in depth: CPython's zipfile already stops at the declared
                        # size (a lying header fails its CRC check), so this cap should never
                        # trigger; it guards against other zip implementations or regressions.
                        if len(out) > self.max_artifact_bytes:
                            raise ConnectorError(
                                ErrorKind.LIMIT_EXCEEDED,
                                f"'{wanted}' exceeded {self.max_artifact_bytes} bytes",
                            )
                return bytes(out)
        except zipfile.BadZipFile as exc:
            raise ConnectorError(
                ErrorKind.INTEGRITY, f"Artifact '{artifact_name}' is not a valid zip: {exc}"
            ) from None

    def _should_retry(self, response: httpx.Response) -> bool:
        if response.status_code == 403 and "retry-after" in response.headers:
            return True  # secondary rate limit
        return super()._should_retry(response)

    def _raise_for_status(self, response: httpx.Response, what: str) -> None:
        code = response.status_code
        if code < 400:
            return
        if code == 403 and response.headers.get("x-ratelimit-remaining") == "0":
            raise ConnectorError(
                ErrorKind.RATE_LIMITED, f"GitHub rate limit hit fetching {what}", 403
            )
        if code in (401, 403):
            hint = (
                "Anonymous access cannot download artifacts or read private repositories."
                if self.anonymous
                else "Check the token has actions:read (and checks:read) on this repository."
            )
            raise AuthError(f"GitHub denied access to {what} (HTTP {code}). {hint}", code)
        if code == 404:
            who = "anonymous access" if self.anonymous else "the token"
            raise NotFoundError(
                f"{what} not found (HTTP 404). It may not exist, or {who} cannot see it."
            )
        if code == 410:
            raise NotFoundError(f"{what} is gone (HTTP 410), e.g. an expired artifact.", 410)
        if code == 429:
            raise ConnectorError(ErrorKind.RATE_LIMITED, f"Rate limited fetching {what}", code)
        if code >= 500:
            raise ConnectorError(ErrorKind.SERVER, f"GitHub server error fetching {what}", code)
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"HTTP {code} fetching {what}", code)

    def _paginate(self, path: str, key: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        url: str | None = f"{self.api_url}{path}"
        query: dict[str, Any] | None = {**params, "per_page": 100}
        for _ in range(MAX_PAGES):
            if url is None:
                return
            response = self._send(url, query)
            self._raise_for_status(response, path)
            try:
                body = response.json()
                items = body[key]
            except (ValueError, KeyError, TypeError) as exc:
                raise ConnectorError(
                    ErrorKind.INVALID_RESPONSE, f"Unexpected page from {path}"
                ) from exc
            if not isinstance(items, list):
                raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Expected a list in '{key}'")
            yield from items
            nxt = response.links.get("next", {}).get("url")
            if nxt and origin_of(nxt) != self._origin:
                raise ConnectorError(
                    ErrorKind.UNSAFE_REDIRECT, "Pagination link left the API origin"
                )
            url, query = nxt, None  # the next link already carries the query
        raise ConnectorError(ErrorKind.LIMIT_EXCEEDED, f"More than {MAX_PAGES} pages from {path}")


def _repo(project: str) -> str:
    project = str(project).strip()
    if not _REPO.match(project):
        raise ConnectorError(
            ErrorKind.INVALID_RESPONSE, f"GitHub repository must be owner/name, got {project!r}"
        )
    owner, name = project.split("/")
    return f"{quote(owner)}/{quote(name)}"


def _verify_digest(archive: bytes, recorded: str | None, name: str) -> None:
    if not recorded:
        return  # older artifacts have no digest; nothing to compare against
    algo, _, expected = recorded.partition(":")
    if algo != "sha256" or not expected:
        return
    actual = hashlib.sha256(archive).hexdigest()
    if actual != expected.lower():
        raise ConnectorError(
            ErrorKind.INTEGRITY,
            f"Artifact '{name}' digest mismatch: GitHub recorded sha256:{expected}, "
            f"downloaded sha256:{actual}",
        )
