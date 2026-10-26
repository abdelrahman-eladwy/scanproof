"""Unified evidence model.

Every scanner adapter turns its tool's raw report into a `ScanEvidence`. The policy
engine only ever sees this model, so supporting a new scanner never touches policy code.

Convention: a field the report does not provide is `None` (unknown), never 0 or [].
"Zero files scanned" and "we don't know how many files were scanned" are different facts.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ScanType(StrEnum):
    SAST = "SAST"
    CONTAINER = "CONTAINER"
    DEPENDENCY = "DEPENDENCY"
    SECRETS = "SECRETS"
    IAC = "IAC"
    SBOM = "SBOM"
    OTHER = "OTHER"  # generic formats (e.g. SARIF) whose producer decides the type


class ScannerError(BaseModel):
    """An error the scanner reported about its own run (not a finding)."""

    level: str | None = None
    type: str | None = None
    message: str
    path: str | None = None


class ScanScope(BaseModel):
    """What the scanner says it looked at."""

    files_scanned: int | None = None
    scanned_paths: list[str] | None = Field(
        default=None, description="Files/targets the scanner reports as scanned"
    )
    skipped_paths: list[str] | None = None
    components: int | None = Field(default=None, description="SBOM component count")
    resources: int | None = Field(default=None, description="IaC resources evaluated")


class FindingsSummary(BaseModel):
    total: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    suppressed: int | None = Field(
        default=None, description="Findings excluded from total because they were suppressed/waived"
    )


class ScanTarget(BaseModel):
    """The artifact a scan was run against (container image for Trivy)."""

    artifact_name: str | None = None
    artifact_type: str | None = None
    image_id: str | None = None
    repo_digests: list[str] | None = None
    repo_tags: list[str] | None = None

    def digests(self) -> set[str]:
        """Bare `sha256:...` digests from `repo@sha256:...` entries."""
        out: set[str] = set()
        for ref in self.repo_digests or []:
            _, _, digest = ref.rpartition("@")
            if digest:
                out.add(digest)
        return out


class EvidenceSource(BaseModel):
    """Where the report came from, filled in when it was fetched from a CI platform."""

    provider: str | None = None
    project: str | None = None
    pipeline_id: int | None = None
    pipeline_sha: str | None = None
    job_id: int | None = None
    job_name: str | None = None
    job_commit_sha: str | None = None
    artifact_path: str | None = None
    local_file: str | None = None


class ScanEvidence(BaseModel):
    schema_version: str = "scanproof.dev/evidence/v1alpha1"
    tool: str
    scan_type: ScanType
    tool_version: str | None = None
    scanner_name: str | None = Field(
        default=None, description="Engine that produced the findings, e.g. CodeQL inside SARIF"
    )

    present: bool = Field(description="A report file was obtained")
    parseable: bool = Field(description="The report parsed as this tool's format")
    parse_error: str | None = None
    report_sha256: str | None = None
    report_bytes: int | None = None

    scanner_errors: list[ScannerError] | None = Field(
        default=None, description="None when the tool's format does not report errors"
    )
    scope: ScanScope | None = None
    results_reported: bool | None = Field(
        default=None, description="The report contained a results section (even if empty)"
    )
    findings: FindingsSummary | None = None
    target: ScanTarget | None = None
    source: EvidenceSource | None = None

    @property
    def scanner_error_count(self) -> int | None:
        return None if self.scanner_errors is None else len(self.scanner_errors)
