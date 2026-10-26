"""Milestone 3: `scanproof verify` orchestration.

Gathers inputs (inspection + evidence per requirement) through a connector, then hands
them to the pure policy engine. A connector error while fetching one requirement's
report makes only that requirement UNKNOWN; an error fetching the pipeline itself is
raised to the caller (nothing can be verified).
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from scanproof import __version__
from scanproof.connectors.base import CIConnector, ConnectorError
from scanproof.evidence.collector import collect_evidence, find_jobs
from scanproof.evidence.models import ScanEvidence
from scanproof.inspection import inspect_pipeline
from scanproof.models import Pipeline
from scanproof.policy.engine import Decision, RequirementInput, RequirementResult, evaluate
from scanproof.policy.models import Policy
from scanproof.scanners import get_adapter


class VerificationReport(BaseModel):
    schema_version: str = "scanproof.dev/verification/v1alpha1"
    scanproof_version: str
    generated_at: datetime
    policy: str
    provider: str
    instance_url: str
    project: str
    pipeline: Pipeline
    decision: Decision
    exit_code: int
    requirements: list[RequirementResult]
    evidence: dict[str, ScanEvidence] = Field(
        default_factory=dict, description="Normalized evidence per requirement id"
    )
    warnings: list[str] = Field(default_factory=list)


def verify_pipeline(
    connector: CIConnector,
    policy: Policy,
    *,
    instance_url: str,
    project: str,
    pipeline_id: int,
) -> VerificationReport:
    inspection = inspect_pipeline(
        connector, instance_url=instance_url, project=project, pipeline_id=pipeline_id
    )
    inputs: dict[str, RequirementInput] = {}
    cache: dict[tuple[int, str, str, str | None], ScanEvidence] = {}

    unreadable = inspection.unreadable_downstream

    def collect(req, job) -> RequirementInput:
        key = (job.latest.id, req.report_path, req.tool.lower(), req.artifact_name)
        try:
            if key not in cache:
                cache[key] = collect_evidence(
                    connector,
                    project=project,
                    pipeline=inspection.pipeline,
                    job=job,
                    report_path=req.report_path,
                    adapter=get_adapter(req.tool),
                    artifact_name=req.artifact_name,
                )
            return RequirementInput(job=job, evidence=cache[key])
        except ConnectorError as exc:
            return RequirementInput(
                job=job,
                evidence_error=(
                    f"Could not fetch {req.report_path}: {exc.kind.value}: {exc.message}"
                ),
            )

    for req in policy.requirements:
        matches, missing = find_jobs(inspection.jobs, req.job_name)
        if not matches:
            inputs[req.id] = RequirementInput(
                absence_unknown=(
                    f"these pipelines could not be read: {', '.join(unreadable)}"
                    if unreadable
                    else None
                )
            )
        elif len(matches) == 1 and not missing:
            inputs[req.id] = collect(req, matches[0])
        else:
            instances = [(job.name, collect(req, job)) for job in matches]
            instances += [(name, RequirementInput()) for name in missing]
            inputs[req.id] = RequirementInput(instances=instances)

    evaluation = evaluate(policy, inspection.pipeline, inputs)
    evidence: dict[str, ScanEvidence] = {}
    for rid, item in inputs.items():
        if item.evidence is not None:
            evidence[rid] = item.evidence
        for name, inst in item.instances or []:
            if inst.evidence is not None:
                evidence[f"{rid} [{name}]"] = inst.evidence
    return VerificationReport(
        scanproof_version=__version__,
        generated_at=datetime.now(UTC),
        policy=policy.name,
        provider=connector.provider,
        instance_url=instance_url,
        project=project,
        pipeline=inspection.pipeline,
        decision=evaluation.decision,
        exit_code=evaluation.decision.exit_code,
        requirements=evaluation.requirements,
        evidence=evidence,
        warnings=[*inspection.warnings, *evaluation.warnings],
    )
