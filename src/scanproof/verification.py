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
from scanproof.evidence.collector import collect_evidence, find_job
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
    cache: dict[tuple[int, str, str], ScanEvidence] = {}

    for req in policy.requirements:
        job = find_job(inspection.jobs, req.job_name)
        if job is None:
            inputs[req.id] = RequirementInput()
            continue
        key = (job.latest.id, req.report_path, req.tool.lower())
        try:
            if key not in cache:
                cache[key] = collect_evidence(
                    connector,
                    project=project,
                    pipeline=inspection.pipeline,
                    job=job,
                    report_path=req.report_path,
                    adapter=get_adapter(req.tool),
                )
            inputs[req.id] = RequirementInput(job=job, evidence=cache[key])
        except ConnectorError as exc:
            inputs[req.id] = RequirementInput(
                job=job,
                evidence_error=(
                    f"Could not fetch {req.report_path}: {exc.kind.value}: {exc.message}"
                ),
            )

    evaluation = evaluate(policy, inspection.pipeline, inputs)
    evidence = {rid: i.evidence for rid, i in inputs.items() if i.evidence is not None}
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
