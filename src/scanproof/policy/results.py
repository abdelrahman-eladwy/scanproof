"""Policy evaluation result types and shared outcome aggregation."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from scanproof.attestation.models import AttestationEvidence
from scanproof.evidence.models import ScanEvidence
from scanproof.models import InspectedJob


class Outcome(StrEnum):
    PASS = "PASS"  # noqa: S105 - outcome name, not a password
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    WAIVED = "WAIVED"  # failed or unknown, but covered by an unexpired waiver in the policy


class Decision(StrEnum):
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"
    INDETERMINATE = "INDETERMINATE"

    @property
    def exit_code(self) -> int:
        return {Decision.VERIFIED: 0, Decision.BLOCKED: 1, Decision.INDETERMINATE: 2}[self]


class CheckResult(BaseModel):
    check: str
    outcome: Outcome
    code: str
    message: str
    waived_unknown: bool = False  # Original outcome was UNKNOWN; preserved in JSON reports.


class RequirementInput(BaseModel):
    """What the orchestrator gathered for one requirement (or one instance of it)."""

    job: InspectedJob | None = None
    evidence: ScanEvidence | None = None
    evidence_error: str | None = Field(
        default=None, description="Why evidence could not be fetched (auth, network...)"
    )
    absence_unknown: str | None = Field(
        default=None,
        description="Job not found, but it may live in a pipeline that couldn't be read",
    )
    instances: list[tuple[str, RequirementInput]] | None = Field(
        default=None,
        description="Parallel / matrix / downstream instances; every one must pass",
    )
    declared_instance: str | None = Field(
        default=None,
        description="This missing instance is a label the requirement declares in `instances`",
    )
    undeclared_instances: list[str] | None = Field(
        default=None,
        description="Matrix legs matched while the requirement declares no `instances`: a "
        "removed leg would go unnoticed (#60)",
    )
    missing_copy: str | None = Field(
        default=None,
        description="This missing instance is a path the requirement declares in `copies`",
    )
    undeclared_copies: list[str] | None = Field(
        default=None,
        description="Prefixed copies matched while the requirement declares no `copies`: a "
        "removed copy would go unnoticed (#65)",
    )
    copies_unbounded: str | None = Field(
        default=None,
        description="The job was found, but pipelines that could not be read may hold more "
        "copies of it, and the requirement declares no `copies` (#71)",
    )
    attestations: list[AttestationEvidence] | None = Field(
        default=None, description="Every bundle found for the attestation subject"
    )
    attestation_error: str | None = Field(
        default=None, description="Why attestations could not be fetched (auth, network...)"
    )


class RequirementResult(BaseModel):
    id: str
    description: str | None
    tool: str
    job_name: str
    job_id: int | None
    outcome: Outcome
    checks: list[CheckResult]
    findings: dict[str, int] | None = Field(
        default=None, description="Reported for context only; findings are never judged"
    )
    instances: list[str] | None = Field(
        default=None, description="Job instances evaluated when job_name matched several"
    )


class Evaluation(BaseModel):
    decision: Decision
    requirements: list[RequirementResult]
    warnings: list[str] = Field(default_factory=list)


def combine(outcomes: list[Outcome]) -> Outcome:
    if not outcomes:
        return Outcome.NOT_APPLICABLE
    if Outcome.FAIL in outcomes:
        return Outcome.FAIL
    if Outcome.UNKNOWN in outcomes:
        return Outcome.UNKNOWN
    if all(o is Outcome.NOT_APPLICABLE for o in outcomes):
        return Outcome.NOT_APPLICABLE
    return Outcome.PASS

