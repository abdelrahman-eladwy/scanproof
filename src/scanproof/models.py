"""Provider-neutral data models for pipeline evidence.

These are what connectors return. Scanner adapters and the policy engine
(milestones 2-3) build on top of them and never see raw provider JSON.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class JobStatus(StrEnum):
    """Normalised job states. Anything unrecognised becomes UNKNOWN, never SUCCESS."""

    SUCCESS = "success"
    FAILED = "failed"
    CANCELED = "canceled"
    SKIPPED = "skipped"
    MANUAL = "manual"
    RUNNING = "running"
    PENDING = "pending"
    CREATED = "created"
    UNKNOWN = "unknown"

    @classmethod
    def from_provider(cls, value: str | None) -> JobStatus:
        aliases = {
            "canceling": cls.CANCELED,
            "preparing": cls.PENDING,
            "waiting_for_resource": cls.PENDING,
            "waiting_for_callback": cls.PENDING,
            "scheduled": cls.PENDING,
        }
        if value is None:
            return cls.UNKNOWN
        try:
            return cls(value)
        except ValueError:
            return aliases.get(value, cls.UNKNOWN)

    @property
    def is_terminal(self) -> bool:
        return self in {JobStatus.SUCCESS, JobStatus.FAILED, JobStatus.CANCELED, JobStatus.SKIPPED}


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")


class ArtifactFile(_Frozen):
    """One entry from a job's artifact list (archive, metadata, trace, report types...)."""

    file_type: str
    filename: str | None = None
    size: int | None = None


class Pipeline(_Frozen):
    id: int
    project_id: int | None = None
    sha: str
    ref: str | None = None
    status: str
    source: str | None = None
    created_at: datetime | None = None
    finished_at: datetime | None = None
    web_url: str | None = None


class Job(_Frozen):
    """A single job attempt. Retries of the same job share a name but have different ids."""

    id: int
    name: str
    stage: str | None = None
    status: JobStatus
    raw_status: str | None = None
    allow_failure: bool = False
    commit_sha: str | None = None
    pipeline_id: int | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    artifacts: tuple[ArtifactFile, ...] = ()
    artifacts_expire_at: datetime | None = None
    web_url: str | None = None
    attempt: int | None = None
    project: str | None = Field(
        default=None,
        description="Project of a downstream (child / multi-project) pipeline's job; artifacts "
        "are fetched from here. None = the inspected project.",
    )
    masking_checked: bool | None = Field(
        default=None,
        description="GitHub: whether a silent step failure (continue-on-error) could be ruled "
        "out. False = could not check; None = not applicable to this platform.",
    )

    @property
    def has_archive(self) -> bool:
        """True when the job uploaded an `artifacts:paths` archive we can read files from."""
        return any(a.file_type == "archive" for a in self.artifacts)


class Downstream(_Frozen):
    """A trigger (bridge) job and the pipeline it started, if any."""

    trigger_name: str
    trigger_status: JobStatus
    pipeline_id: int | None = None
    project: str | None = None
    sha: str | None = None
    status: str | None = None


class InspectedJob(BaseModel):
    """The effective (latest) attempt of a job name, plus its retry history."""

    name: str
    stage: str | None
    latest: Job
    attempt_ids: list[int] = Field(description="All attempt ids for this name, oldest first")
    commit_matches_pipeline: bool | None = Field(
        default=None,
        description="Job commit SHA equals pipeline SHA; None if the job reported none.",
    )

    @property
    def attempts(self) -> int:
        return len(self.attempt_ids)


class InspectionReport(BaseModel):
    """Output of `scanproof inspect`: what the pipeline contains, with no judgement applied."""

    schema_version: str = "scanproof.dev/inspection/v1alpha1"
    scanproof_version: str
    generated_at: datetime
    provider: str
    instance_url: str
    project: str
    pipeline: Pipeline
    jobs: list[InspectedJob]
    downstream: list[Downstream] = Field(default_factory=list)
    unreadable_downstream: list[str] = Field(
        default_factory=list,
        description="Downstream pipelines that exist but could not be read; a job that seems "
        "absent may be in one of them, so absence is unknown rather than a failure",
    )
    warnings: list[str] = Field(default_factory=list)
