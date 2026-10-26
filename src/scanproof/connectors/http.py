"""Shared, security-hardened HTTP layer for CI platform connectors.

Every connector (GitLab, GitHub, ...) inherits these guarantees (see docs/security.md):
  * The token is sent as `Authorization: Bearer`, only to the configured API origin, never in a
    URL, never logged, never in `repr`.
  * Redirects are followed manually: credentials are dropped on cross-origin redirects (e.g. to
    object storage for artifacts) and any HTTPS -> HTTP downgrade is refused.
  * TLS verification cannot be disabled; private CAs are supported via a CA bundle.
  * Downloads are streamed and capped; retries back off and respect Retry-After.
  * Anonymous access must be requested explicitly and never sends a token.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, ClassVar
from urllib.parse import urljoin, urlsplit

import httpx

from scanproof import __version__
from scanproof.connectors.base import AuthError, CIConnector, ConnectorError, ErrorKind

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
DEFAULT_MAX_ARTIFACT_BYTES = 50 * 1024 * 1024
MAX_PAGES = 100
MAX_REDIRECTS = 3


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
        self.anonymous = anonymous
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.max_artifact_bytes = max_artifact_bytes
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
        if self._token and origin_of(url) == self._origin:
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
                        ErrorKind.NETWORK,
                        f"Network error calling {self.label}: {type(exc).__name__}",
                    ) from exc
                self._backoff(attempt, None)
                attempt += 1
                continue

            if self._should_retry(response) and attempt < self.max_retries:
                retry_after = response.headers.get("Retry-After")
                response.close()
                self._backoff(attempt, retry_after)
                attempt += 1
                continue
            return response

    def _should_retry(self, response: httpx.Response) -> bool:
        return response.status_code in RETRYABLE_STATUS

    def _follow(self, url: str, params: dict[str, Any] | None, *, stream: bool) -> httpx.Response:
        # httpx.URL(url, params=None) drops url's own query string (e.g. pagination links),
        # so merge explicit params into the existing query instead.
        current = httpx.URL(url)
        if params:
            current = current.copy_merge_params(params)
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

    def _download(self, url: str, what: str | None = None) -> bytes:
        response = self._send(url, stream=True)
        try:
            self._raise_for_status(response, what or urlsplit(url).path)
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
