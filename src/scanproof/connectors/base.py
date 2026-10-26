"""Provider-neutral connector contract.

Every CI/CD provider (GitLab today; GitHub Actions or Jenkins later) implements
`CIConnector`. The rest of ScanProof only depends on this interface and on the
models in `scanproof.models`, never on provider-specific JSON.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum

from scanproof.models import Job, Pipeline


class ErrorKind(StrEnum):
    """Why the connector could not obtain evidence.

    Every kind maps to an UNKNOWN / INDETERMINATE outcome later on: an error
    talking to the CI platform is never evidence that a control passed or failed.
    """

    AUTH = "AUTH"  # 401 / 403: token missing, expired, or lacks scope
    NOT_FOUND = "NOT_FOUND"  # 404: project, pipeline, job or artifact does not exist (or is hidden)
    RATE_LIMITED = "RATE_LIMITED"  # 429 after retries were exhausted
    SERVER = "SERVER"  # 5xx after retries were exhausted
    NETWORK = "NETWORK"  # DNS, TLS, timeouts, connection resets
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"  # artifact larger than the configured cap
    UNSAFE_REDIRECT = "UNSAFE_REDIRECT"  # redirect we refused to follow
    INVALID_RESPONSE = "INVALID_RESPONSE"  # response did not match the expected shape


class ConnectorError(Exception):
    """Raised when evidence cannot be retrieved. Messages never include credentials."""

    def __init__(self, kind: ErrorKind, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.status_code = status_code

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind.value, "message": self.message, "status_code": self.status_code}


class AuthError(ConnectorError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(ErrorKind.AUTH, message, status_code)


class NotFoundError(ConnectorError):
    def __init__(self, message: str, status_code: int | None = 404) -> None:
        super().__init__(ErrorKind.NOT_FOUND, message, status_code)


class CIConnector(ABC):
    """Read-only access to pipeline evidence on a CI/CD platform."""

    provider: str

    @abstractmethod
    def get_pipeline(self, project: str, pipeline_id: int) -> Pipeline: ...

    @abstractmethod
    def list_jobs(self, project: str, pipeline_id: int) -> list[Job]:
        """Return every job attempt in the pipeline, including retried attempts."""

    @abstractmethod
    def download_artifact_file(self, project: str, job_id: int, artifact_path: str) -> bytes:
        """Download a single file from a job's artifacts archive, enforcing size limits."""

    def close(self) -> None:  # pragma: no cover - default no-op
        return None

    def __enter__(self) -> CIConnector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
