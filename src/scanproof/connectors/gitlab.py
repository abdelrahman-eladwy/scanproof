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

import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import httpx

from scanproof import __version__
from scanproof.connectors.base import (
    AuthError,
    CIConnector,
    ConnectorError,
    ErrorKind,
    NotFoundError,
)
from scanproof.models import ArtifactFile, Job, JobStatus, Pipeline

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
DEFAULT_MAX_ARTIFACT_BYTES = 50 * 1024 * 1024
MAX_PAGES = 100  # 100 pages x 100 jobs: far beyond any real pipeline
MAX_REDIRECTS = 3


def _origin(url: str | httpx.URL) -> tuple[str, str, int | None]:
    parts = urlsplit(str(url))
    default_port = {"https": 443, "http": 80}.get(parts.scheme)
    return (parts.scheme, (parts.hostname or "").lower(), parts.port or default_port)


class GitLabConnector(CIConnector):
    provider = "gitlab"

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 30.0,
        ca_bundle: str | None = None,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not token:
            raise AuthError("No GitLab token provided. Set GITLAB_TOKEN (read_api scope).")
        base_url = base_url.rstrip("/")
        if urlsplit(base_url).scheme != "https" and not _is_loopback(base_url):
            raise ConnectorError(ErrorKind.NETWORK, f"Refusing non-HTTPS GitLab URL: {base_url}")
        self.base_url = base_url
        self.api_url = f"{base_url}/api/v4"
        self._origin = _origin(base_url)
        self._token = token
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.max_artifact_bytes = max_artifact_bytes
        self._sleep = sleep
        self._client = httpx.Client(
            timeout=timeout,
            verify=ca_bundle if ca_bundle else True,
            follow_redirects=False,
            headers={"User-Agent": f"scanproof/{__version__}", "Accept": "application/json"},
            transport=transport,
        )

    def __repr__(self) -> str:  # never expose the token
        return f"GitLabConnector(base_url={self.base_url!r})"

    # ------------------------------------------------------------------ public API

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
        except (KeyError, TypeError, ValueError) as exc:
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

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------ HTTP plumbing

    def _auth_headers_for(self, url: str | httpx.URL) -> dict[str, str]:
        if _origin(url) == self._origin:
            return {"Authorization": f"Bearer {self._token}"}
        return {}

    def _send(
        self, url: str, params: dict[str, Any] | None = None, *, stream: bool = False
    ) -> httpx.Response:
        """GET with retries and manual, credential-safe redirect handling."""
        attempt = 0
        while True:
            try:
                response = self._follow(url, params, stream=stream)
            except httpx.TransportError as exc:
                if attempt >= self.max_retries:
                    raise ConnectorError(
                        ErrorKind.NETWORK, f"Network error calling GitLab: {type(exc).__name__}"
                    ) from exc
                self._backoff(attempt, None)
                attempt += 1
                continue

            if response.status_code in RETRYABLE_STATUS and attempt < self.max_retries:
                retry_after = response.headers.get("Retry-After")
                response.close()
                self._backoff(attempt, retry_after)
                attempt += 1
                continue
            return response

    def _follow(self, url: str, params: dict[str, Any] | None, *, stream: bool) -> httpx.Response:
        current: httpx.URL = httpx.URL(url, params=params)
        for _ in range(MAX_REDIRECTS + 1):
            request = self._client.build_request(
                "GET", current, headers=self._auth_headers_for(current)
            )
            response = self._client.send(request, stream=stream)
            if not response.is_redirect:
                return response
            location = response.headers.get("Location", "")
            response.close()
            target = httpx.URL(urljoin(str(current), location))
            if current.scheme == "https" and target.scheme != "https":
                raise ConnectorError(
                    ErrorKind.UNSAFE_REDIRECT,
                    f"Refused redirect from HTTPS to {target.scheme.upper()} ({target.host})",
                    response.status_code,
                )
            current = target
        raise ConnectorError(ErrorKind.UNSAFE_REDIRECT, f"More than {MAX_REDIRECTS} redirects")

    def _backoff(self, attempt: int, retry_after: str | None) -> None:
        delay = self.backoff_seconds * (2**attempt)
        if retry_after and retry_after.isdigit():
            delay = max(delay, float(retry_after))
        self._sleep(min(delay, 60.0))

    def _raise_for_status(self, response: httpx.Response, what: str) -> None:
        code = response.status_code
        if code < 400:
            return
        if code in (401, 403):
            raise AuthError(
                f"GitLab denied access to {what} (HTTP {code}). "
                "Check the token is valid and has read_api scope on this project.",
                code,
            )
        if code == 404:
            raise NotFoundError(
                f"{what} not found (HTTP 404). It may not exist, or the token cannot see it."
            )
        if code == 429:
            raise ConnectorError(ErrorKind.RATE_LIMITED, f"Rate limited fetching {what}", code)
        if code >= 500:
            raise ConnectorError(ErrorKind.SERVER, f"GitLab server error fetching {what}", code)
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"HTTP {code} fetching {what}", code)

    def _get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self._send(f"{self.api_url}{path}", params)
        self._raise_for_status(response, path)
        try:
            return response.json()
        except ValueError as exc:
            raise ConnectorError(
                ErrorKind.INVALID_RESPONSE, f"Non-JSON response from {path}"
            ) from exc

    def _paginate(self, path: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        page = 1
        for _ in range(MAX_PAGES):
            response = self._send(
                f"{self.api_url}{path}", {**params, "per_page": 100, "page": page}
            )
            self._raise_for_status(response, path)
            try:
                items = response.json()
            except ValueError as exc:
                raise ConnectorError(
                    ErrorKind.INVALID_RESPONSE, f"Non-JSON page from {path}"
                ) from exc
            if not isinstance(items, list):
                raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Expected a list from {path}")
            yield from items
            next_page = response.headers.get("x-next-page", "").strip()
            if not next_page or not items:
                return
            page = int(next_page)
        raise ConnectorError(ErrorKind.LIMIT_EXCEEDED, f"More than {MAX_PAGES} pages from {path}")

    def _download(self, url: str) -> bytes:
        response = self._send(url, stream=True)
        try:
            self._raise_for_status(response, urlsplit(url).path)
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > self.max_artifact_bytes:
                raise ConnectorError(
                    ErrorKind.LIMIT_EXCEEDED,
                    f"Artifact is {int(declared)} bytes; limit is {self.max_artifact_bytes}",
                )
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > self.max_artifact_bytes:
                    raise ConnectorError(
                        ErrorKind.LIMIT_EXCEEDED,
                        f"Artifact exceeded {self.max_artifact_bytes} bytes while streaming",
                    )
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            response.close()


# ---------------------------------------------------------------------- helpers


def _is_loopback(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


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
    except (KeyError, TypeError, ValueError) as exc:
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Unexpected job payload: {exc}") from exc
