"""GitLab REST API v4 connector (read-only).

Endpoints used:
  GET /projects/:id/pipelines/:pipeline_id
  GET /projects/:id/pipelines/:pipeline_id/jobs?include_retried=true
  GET /projects/:id/jobs/:job_id/artifacts/*artifact_path

Security properties (see docs/security.md):
  * The token is sent as `Authorization: Bearer`, never in a URL, and never logged.
  * Redirects are followed manually. Credentials are only sent to the configured
    GitLab origin; cross-origin redirects (e.g. object storage for artifacts) are
    followed without credentials, and any downgrade to plain HTTP is refused.
  * TLS verification cannot be disabled; self-hosted users pass a CA bundle instead.
  * Artifact downloads are streamed and capped.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import quote

import httpx

from scanproof.connectors.base import AuthError, ConnectorError, ErrorKind, NotFoundError
from scanproof.connectors.http import (
    DEFAULT_MAX_ARTIFACT_BYTES,
    MAX_PAGES,
    HttpConnector,
    origin_of,
)
from scanproof.models import ArtifactFile, Downstream, Job, JobStatus, Pipeline

_JOB_URI = re.compile(r"^(?P<origin>https://[^/]+)/(?P<path>.+)/-/jobs/(?P<job>\d+)/?$")


class GitLabConnector(HttpConnector):
    provider = "gitlab"
    label = "GitLab"
    auth_hint = "Set GITLAB_TOKEN (read_api scope)."

    def __init__(
        self,
        base_url: str,
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
        **limits: Any,  # request_deadline, run_budget, clock (see HttpConnector)
    ) -> None:
        super().__init__(
            base_url,
            token,
            api_url=f"{base_url.rstrip('/')}/api/v4",
            anonymous=anonymous,
            timeout=timeout,
            ca_bundle=ca_bundle,
            max_retries=max_retries,
            backoff_seconds=backoff_seconds,
            max_artifact_bytes=max_artifact_bytes,
            transport=transport,
            sleep=sleep,
            **limits,
        )

    # ------------------------------------------------------------------ public API

    def run_matches(
        self, invocation_uri: str | None, pipeline: Pipeline, job_ids: set[int]
    ) -> bool | None:
        """Fulcio's GitLab claims: https://<instance>/<project path>/-/jobs/<job id>. The job must
        be one of this pipeline's jobs (child pipelines included); job ids are instance-wide."""
        if not invocation_uri:
            return None
        m = _JOB_URI.match(invocation_uri)
        if not m:
            return None
        if origin_of(m.group("origin")) != origin_of(self.base_url):
            return False
        return int(m.group("job")) in job_ids

    def get_pipeline(self, project: str, pipeline_id: int) -> Pipeline:
        data = self._get_json(f"/projects/{_project_ref(project)}/pipelines/{pipeline_id}")
        try:
            return Pipeline(
                id=data["id"],
                project_id=data.get("project_id"),
                sha=data["sha"],
                ref=data.get("ref"),
                status=data["status"],
                source=data.get("source"),
                created_at=data.get("created_at"),
                finished_at=data.get("finished_at"),
                web_url=data.get("web_url"),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ConnectorError(
                ErrorKind.INVALID_RESPONSE, f"Unexpected pipeline payload: {exc}"
            ) from exc

    def list_jobs(self, project: str, pipeline_id: int) -> list[Job]:
        path = f"/projects/{_project_ref(project)}/pipelines/{pipeline_id}/jobs"
        jobs: list[Job] = []
        for item in self._paginate(path, {"include_retried": "true"}):
            jobs.append(_parse_job(item))
        return sorted(jobs, key=lambda j: j.id)

    def download_artifact_file(self, project: str, job_id: int, artifact_path: str) -> bytes:
        safe_path = quote(artifact_path.lstrip("/"), safe="/")
        if ".." in artifact_path.split("/"):
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, "Artifact path must not contain '..'")
        url = f"{self.api_url}/projects/{_project_ref(project)}/jobs/{job_id}/artifacts/{safe_path}"
        return self._download(url)

    def list_downstream(self, project: str, pipeline_id: int) -> list[Downstream]:
        path = f"/projects/{_project_ref(project)}/pipelines/{pipeline_id}/bridges"
        out: list[Downstream] = []
        for item in self._paginate(path, {}):
            try:
                ds = item.get("downstream_pipeline") or {}
                if not isinstance(ds, dict):
                    raise TypeError("downstream_pipeline must be an object")
                out.append(
                    Downstream(
                        trigger_name=item["name"],
                        trigger_status=JobStatus.from_provider(item.get("status")),
                        pipeline_id=ds.get("id"),
                        project=str(ds["project_id"]) if ds.get("project_id") is not None else None,
                        sha=ds.get("sha"),
                        status=ds.get("status"),
                    )
                )
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise ConnectorError(
                    ErrorKind.INVALID_RESPONSE, f"Unexpected bridge payload: {exc}"
                ) from exc
        return out

    def fetch_report(
        self, project: str, job: Job, report_path: str, artifact_name: str | None = None
    ) -> bytes:
        if not job.has_archive:
            raise NotFoundError("Job uploaded no artifacts archive", status_code=None)
        try:
            return self.download_artifact_file(job.project or project, job.id, report_path)
        except NotFoundError:
            raise NotFoundError(
                f"'{report_path}' not found in job artifacts (never uploaded, or expired)"
            ) from None

    def _raise_for_status(self, response: httpx.Response, what: str) -> None:
        code = response.status_code
        if code < 400:
            return
        who = "anonymous access" if self.anonymous else "the token"
        if code in (401, 403):
            hint = (
                "Anonymous mode only works for public projects with public pipelines."
                if self.anonymous
                else "Check the token is valid and has read_api scope on this project."
            )
            raise AuthError(f"GitLab denied access to {what} (HTTP {code}). {hint}", code)
        if code == 404:
            raise NotFoundError(
                f"{what} not found (HTTP 404). It may not exist, or {who} cannot see it."
            )
        if code == 429:
            hint = (
                " Anonymous access is heavily rate limited (gitlab.com: 60 API requests per hour "
                "per IP); use a read_api token instead of --anonymous."
                if self.anonymous
                else ""
            )
            raise ConnectorError(
                ErrorKind.RATE_LIMITED, f"Rate limited fetching {what}.{hint}", code
            )
        if code >= 500:
            raise ConnectorError(ErrorKind.SERVER, f"GitLab server error fetching {what}", code)
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"HTTP {code} fetching {what}", code)

    def _paginate(self, path: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        page = 1
        for _ in range(MAX_PAGES):
            response = self._send(
                f"{self.api_url}{path}", {**params, "per_page": 100, "page": page}
            )
            self._raise_for_status(response, path)
            try:
                items = response.json()
            except (ValueError, RecursionError) as exc:
                raise ConnectorError(
                    ErrorKind.INVALID_RESPONSE, f"Non-JSON page from {path}"
                ) from exc
            if not isinstance(items, list):
                raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Expected a list from {path}")
            yield from items
            next_page = response.headers.get("x-next-page", "").strip()
            if not next_page or not items:
                return
            # Pages only move forward; anything else is a loop or a broken header.
            if not next_page.isdigit() or int(next_page) <= page:
                raise ConnectorError(
                    ErrorKind.INVALID_RESPONSE,
                    f"Pagination of {path} did not advance (page {page} -> {next_page!r})",
                )
            page = int(next_page)
        raise ConnectorError(ErrorKind.LIMIT_EXCEEDED, f"More than {MAX_PAGES} pages from {path}")


# ---------------------------------------------------------------------- helpers


def _project_ref(project: str) -> str:
    """Accept a numeric id or a full path like `group/sub/project`."""
    project = str(project).strip()
    if not project:
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, "Project id/path is empty")
    return project if project.isdigit() else quote(project, safe="")


def _parse_job(item: dict[str, Any]) -> Job:
    try:
        artifacts = tuple(
            ArtifactFile(
                file_type=a.get("file_type", "unknown"),
                filename=a.get("filename"),
                size=a.get("size"),
            )
            for a in item.get("artifacts") or []
        )
        commit = item.get("commit") or {}
        pipeline = item.get("pipeline") or {}
        raw_status = item.get("status")
        return Job(
            id=item["id"],
            name=item["name"],
            stage=item.get("stage"),
            status=JobStatus.from_provider(raw_status),
            raw_status=raw_status,
            allow_failure=bool(item.get("allow_failure", False)),
            commit_sha=commit.get("id"),
            pipeline_id=pipeline.get("id"),
            created_at=item.get("created_at"),
            started_at=item.get("started_at"),
            finished_at=item.get("finished_at"),
            artifacts=artifacts,
            artifacts_expire_at=item.get("artifacts_expire_at"),
            web_url=item.get("web_url"),
        )
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Unexpected job payload: {exc}") from exc
