"""Shared, security-hardened HTTP layer for CI platform connectors.

Every connector (GitLab, GitHub, ...) inherits these guarantees (see docs/security.md):
  * The token is sent in the `Authorization` header (Bearer, or Basic user:token where the
    platform requires it: Jenkins, Azure DevOps PATs, Bitbucket API tokens), only to the
    configured API origin, never in a URL, never logged, never in `repr`. Username and token
    both come from environment variables.
  * Redirects are followed manually: credentials are dropped on cross-origin redirects (e.g. to
    object storage for artifacts) and any HTTPS -> HTTP downgrade is refused.
  * TLS verification cannot be disabled; private CAs are supported via a CA bundle.
  * Every response body (API pages included) is streamed and capped; retries back off and
    respect Retry-After.
  * Time is bounded: each response body must arrive within `request_deadline` seconds (a server
    dripping bytes never trips the per-read timeout), and a connector's requests together within
    `run_budget` seconds. Both end as a NETWORK error, i.e. UNKNOWN, never as a pass.
  * Anonymous access must be requested explicitly and never sends a token.
"""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, ClassVar, Literal
from urllib.parse import urljoin, urlsplit

import httpx

from scanproof import __version__
from scanproof.archives import ZipTooLarge, check_zip_directory
from scanproof.connectors.base import (
    AuthError,
    CIConnector,
    ConnectorError,
    ErrorKind,
    NotFoundError,
)

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
DEFAULT_MAX_ARTIFACT_BYTES = 50 * 1024 * 1024
MAX_PAGES = 100
MAX_REDIRECTS = 3
DEFAULT_REQUEST_DEADLINE = 300.0  # seconds for one response body, retries not included
DEFAULT_RUN_BUDGET = 1800.0  # seconds for everything one connector does
MAX_RETRY_WAIT = 60.0  # longest single wait before a retry; longer Retry-After = give up
_REBUILT_DROP = frozenset({"content-encoding", "content-length", "transfer-encoding"})


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Retry-After as seconds (delta-seconds or HTTP-date, RFC 9110 10.2.3), else None.

    A date in the past means "now" (0). Anything unparseable is ignored, so the normal
    bounded backoff applies; it can never extend a wait beyond MAX_RETRY_WAIT.
    """
    if value is None:
        return None
    text = value.strip()
    if text.isdigit():
        return float(text)
    if not text or text[0].isdigit() or text[0] in "+-":
        return None
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        return None
    return max(0.0, (when - (now or datetime.now(UTC))).total_seconds())


def origin_of(url: str | httpx.URL) -> tuple[str, str, int | None]:
    parts = urlsplit(str(url))
    default_port = {"https": 443, "http": 80}.get(parts.scheme)
    return (parts.scheme, (parts.hostname or "").lower(), parts.port or default_port)


def is_loopback(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


class HttpConnector(CIConnector):
    """Base for HTTP API connectors. Subclasses set `label`, `auth_hint` and `api_url`."""

    label: ClassVar[str] = "CI platform"
    auth_hint: ClassVar[str] = "Set a read-only token."
    extra_headers: ClassVar[dict[str, str]] = {}
    default_auth_scheme: ClassVar[Literal["bearer", "basic"]] = "bearer"

    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        api_url: str,
        anonymous: bool = False,
        timeout: float = 30.0,
        ca_bundle: str | None = None,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        username: str | None = None,
        auth_scheme: Literal["bearer", "basic"] | None = None,
        request_deadline: float = DEFAULT_REQUEST_DEADLINE,
        run_budget: float = DEFAULT_RUN_BUDGET,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        # Anonymous access must be asked for explicitly, so a token that silently failed to
        # load can never degrade into unauthenticated requests.
        if anonymous and token:
            raise AuthError("Use either a token or anonymous mode, not both.")
        if not anonymous and not token:
            raise AuthError(f"No {self.label} token provided. {self.auth_hint}")
        base_url = base_url.rstrip("/")
        api_url = api_url.rstrip("/")
        for url in (base_url, api_url):
            if urlsplit(url).scheme != "https" and not is_loopback(url):
                raise ConnectorError(
                    ErrorKind.NETWORK, f"Refusing non-HTTPS {self.label} URL: {url}"
                )
        self.base_url = base_url
        self.api_url = api_url
        self._origin = origin_of(api_url)
        self._token = None if anonymous else token
        self.auth_scheme = auth_scheme or self.default_auth_scheme
        if self.auth_scheme not in ("bearer", "basic"):
            raise AuthError(f"Unknown auth scheme {self.auth_scheme!r}")
        if username is not None and (":" in username or not username.isprintable()):
            raise AuthError("Username must be printable and must not contain ':'")
        self._username = username
        self.anonymous = anonymous
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.max_artifact_bytes = max_artifact_bytes
        self.request_deadline = request_deadline
        self.run_budget = run_budget
        self._clock = clock
        self._started = clock()
        self._sleep = sleep
        self._client = httpx.Client(
            timeout=timeout,
            verify=ca_bundle if ca_bundle else True,
            follow_redirects=False,
            headers={
                "User-Agent": f"scanproof/{__version__}",
                "Accept": "application/json",
                **self.extra_headers,
            },
            transport=transport,
        )

    def __repr__(self) -> str:  # never expose the token
        return f"{type(self).__name__}(base_url={self.base_url!r}, anonymous={self.anonymous})"

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------ requests

    def _auth_headers_for(self, url: str | httpx.URL) -> dict[str, str]:
        if not self._token or origin_of(url) != self._origin:
            return {}
        if self.auth_scheme == "basic":
            pair = f"{self._username or ''}:{self._token}".encode()
            return {"Authorization": f"Basic {base64.b64encode(pair).decode()}"}
        return {"Authorization": f"Bearer {self._token}"}

    def _send(
        self, url: str, params: dict[str, Any] | None = None, *, stream: bool = False
    ) -> httpx.Response:
        """GET with retries and manual, credential-safe redirect handling.

        A retry happens only if its wait is allowed by the server's Retry-After (at most
        MAX_RETRY_WAIT) and still fits in the run budget; otherwise the real outcome is
        reported now (the last response, or a NETWORK error) instead of sleeping first.
        """
        attempt = 0
        while True:
            self._check_budget()
            try:
                response = self._follow(url, params, stream=stream)
            except httpx.TransportError as exc:
                delay = self._retry_delay(attempt, None)
                if delay is None:
                    raise ConnectorError(
                        ErrorKind.NETWORK,
                        f"Network error calling {self.label}: {type(exc).__name__}",
                    ) from exc
                self._sleep(delay)
                attempt += 1
                continue

            if self._should_retry(response):
                delay = self._retry_delay(attempt, response.headers.get("Retry-After"))
                if delay is not None:
                    response.close()
                    self._sleep(delay)
                    attempt += 1
                    continue
            return response

    def _should_retry(self, response: httpx.Response) -> bool:
        return response.status_code in RETRYABLE_STATUS

    def _check_budget(self) -> None:
        if self._clock() - self._started > self.run_budget:
            raise ConnectorError(
                ErrorKind.NETWORK,
                f"{self.label} requests exceeded the {self.run_budget:.0f}s time budget",
            )

    def _body(self, response: httpx.Response, what: str):
        """Yield the (decoded) body, enforcing the size cap and the per-response deadline."""
        started = self._clock()
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > self.max_artifact_bytes:
                raise ConnectorError(
                    ErrorKind.LIMIT_EXCEEDED,
                    f"{what} exceeded {self.max_artifact_bytes} bytes while streaming",
                )
            self._check_budget()
            if self._clock() - started > self.request_deadline:
                raise ConnectorError(
                    ErrorKind.NETWORK,
                    f"{what} took longer than {self.request_deadline:.0f}s to download",
                )
            yield chunk
        # Even a stream that yields no chunks can consume the entire deadline.
        self._check_budget()
        if self._clock() - started > self.request_deadline:
            raise ConnectorError(
                ErrorKind.NETWORK,
                f"{what} took longer than {self.request_deadline:.0f}s to download",
            )

    def _follow(self, url: str, params: dict[str, Any] | None, *, stream: bool) -> httpx.Response:
        # httpx.URL(url, params=None) drops url's own query string (e.g. pagination links),
        # so merge explicit params into the existing query instead.
        current = httpx.URL(url)
        # Artifact URLs may come from untrusted provider metadata rather than a redirect.
        # Enforce the same transport and credential rules before the first request.
        if current.username or current.password:
            raise ConnectorError(
                ErrorKind.UNSAFE_REDIRECT, "Refused request URL containing credentials"
            )
        if current.scheme != "https" and not (
            current.scheme == "http" and is_loopback(str(current))
        ):
            raise ConnectorError(
                ErrorKind.UNSAFE_REDIRECT, "Refused non-HTTPS non-loopback request URL"
            )
        if params:
            current = current.copy_merge_params(params)
        for _ in range(MAX_REDIRECTS + 1):
            request = self._client.build_request(
                "GET", current, headers=self._auth_headers_for(current)
            )
            response = self._client.send(request, stream=True)
            if not response.is_redirect:
                if stream:
                    return response
                # Read the whole body here, capped and against the deadline; a transport error
                # mid-body reaches _send's retry loop like any other.
                try:
                    content = b"".join(self._body(response, current.path))
                finally:
                    response.close()
                headers = [
                    (k, v)
                    for k, v in response.headers.multi_items()
                    if k.lower() not in _REBUILT_DROP
                ]
                return httpx.Response(
                    response.status_code, headers=headers, content=content, request=request
                )
            location = response.headers.get("Location", "")
            response.close()
            target = httpx.URL(urljoin(str(current), location))
            if target.username or target.password:
                raise ConnectorError(
                    ErrorKind.UNSAFE_REDIRECT, "Refused redirect URL containing credentials"
                )
            if current.scheme == "https" and target.scheme != "https":
                raise ConnectorError(
                    ErrorKind.UNSAFE_REDIRECT,
                    f"Refused redirect from HTTPS to {target.scheme.upper()} ({target.host})",
                    response.status_code,
                )
            if target.scheme != "https" and not (
                target.scheme == "http" and is_loopback(str(target))
            ):
                raise ConnectorError(
                    ErrorKind.UNSAFE_REDIRECT, "Refused redirect to non-HTTPS non-loopback URL"
                )
            current = target
        raise ConnectorError(ErrorKind.UNSAFE_REDIRECT, f"More than {MAX_REDIRECTS} redirects")

    def _retry_delay(self, attempt: int, retry_after: str | None) -> float | None:
        """Seconds to wait before the next attempt, or None when retrying is pointless."""
        if attempt >= self.max_retries:
            return None
        delay = self.backoff_seconds * (2**attempt)
        server_wait = parse_retry_after(retry_after)
        if server_wait is not None:
            if server_wait > MAX_RETRY_WAIT:
                return None  # the server says not yet: retrying sooner only burns budget
            delay = max(delay, server_wait)
        delay = min(delay, MAX_RETRY_WAIT)
        remaining = self.run_budget - (self._clock() - self._started)
        if delay >= remaining:
            return None
        return delay

    def _raise_for_status(self, response: httpx.Response, what: str) -> None:
        code = response.status_code
        if code < 400:
            return
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"HTTP {code} fetching {what}", code)

    def _extract(self, archive: bytes, report_path: str, artifact_name: str) -> bytes:
        """Read one member of an artifact zip, size-capped, refusing '..' paths."""
        wanted = report_path.strip().lstrip("/")
        while wanted.startswith("./"):
            wanted = wanted[2:]
        if ".." in wanted.split("/"):
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, "Report path must not contain '..'")
        try:
            check_zip_directory(archive)
        except ZipTooLarge as exc:
            raise ConnectorError(
                ErrorKind.LIMIT_EXCEEDED, f"Artifact '{artifact_name}': {exc}"
            ) from None
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                names = zf.namelist()
                if wanted not in names:
                    sample = ", ".join(names[:10]) or "(empty)"
                    raise NotFoundError(
                        f"'{wanted}' not found in artifact '{artifact_name}' (contains: {sample})",
                        None,
                    )
                matches = [entry for entry in zf.infolist() if entry.filename == wanted]
                if len(matches) != 1:
                    raise ConnectorError(
                        ErrorKind.INVALID_RESPONSE,
                        f"Artifact '{artifact_name}' has ambiguous duplicate report path "
                        f"'{wanted}'",
                    )
                info = matches[0]
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

    def _raise_standard(self, response: httpx.Response, what: str, hint: str = "") -> None:
        """Common status mapping for platforms without special cases: auth problems, missing
        evidence and platform trouble are kept apart (each maps to a different outcome)."""
        code = response.status_code
        if code < 400:
            return
        if code in (401, 403):
            raise AuthError(
                f"{self.label} denied access to {what} (HTTP {code}). {hint}".strip(), code
            )
        if code in (404, 410):
            raise NotFoundError(f"{what} not found (HTTP {code}).", code)
        if code == 429:
            raise ConnectorError(ErrorKind.RATE_LIMITED, f"Rate limited fetching {what}", code)
        if code >= 500:
            raise ConnectorError(
                ErrorKind.SERVER, f"{self.label} server error fetching {what}", code
            )
        raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"HTTP {code} fetching {what}", code)

    def _get_json_capped(self, url: str, what: str) -> Any:
        """GET JSON through the capped streaming path (for platforms with large documents)."""
        body = self._download(url, what)
        try:
            return json.loads(body)
        except (ValueError, RecursionError) as exc:
            raise ConnectorError(
                ErrorKind.INVALID_RESPONSE, f"Non-JSON response for {what}"
            ) from exc

    def _get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self._send(f"{self.api_url}{path}", params)
        self._raise_for_status(response, path)
        try:
            return response.json()
        except ValueError as exc:
            raise ConnectorError(
                ErrorKind.INVALID_RESPONSE, f"Non-JSON response from {path}"
            ) from exc

    def _download(self, url: str, what: str | None = None) -> bytes:
        """Stream a download with a size cap. A connection that drops mid-body is retried from
        the start (found in complex-scenario testing: it used to escape as httpx.ReadError)."""
        attempt = 0
        while True:
            try:
                return self._download_once(url, what)
            except httpx.TransportError as exc:
                delay = self._retry_delay(attempt, None)
                if delay is None:
                    raise ConnectorError(
                        ErrorKind.NETWORK,
                        f"Download from {self.label} kept failing mid-transfer: "
                        f"{type(exc).__name__}",
                    ) from exc
                self._sleep(delay)
                attempt += 1

    def _download_once(self, url: str, what: str | None) -> bytes:
        return self._download_page(url, what)[0]

    def _download_page(
        self, url: str, what: str | None = None, params: dict[str, Any] | None = None
    ) -> tuple[bytes, str | None]:
        """Capped download that also returns the `Link: rel=next` URL (same API origin only)."""
        response = self._send(url, params, stream=True)
        try:
            body = self._read_capped(response, what or urlsplit(url).path)
            nxt = response.links.get("next", {}).get("url")
            if nxt and origin_of(nxt) != self._origin:
                raise ConnectorError(
                    ErrorKind.UNSAFE_REDIRECT, "Pagination link left the API origin"
                )
            return body, nxt
        finally:
            response.close()

    def _read_capped(self, response: httpx.Response, what: str) -> bytes:
        self._raise_for_status(response, what)
        declared = response.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > self.max_artifact_bytes:
            raise ConnectorError(
                ErrorKind.LIMIT_EXCEEDED,
                f"Artifact is {int(declared)} bytes; limit is {self.max_artifact_bytes}",
            )
        return b"".join(self._body(response, f"Artifact {what}"))
