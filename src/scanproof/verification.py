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
from scanproof.attestation.models import AttestationEvidence
from scanproof.attestation.verify import TrustConfig, verify_bundles
from scanproof.connectors.base import CIConnector, ConnectorError, NotFoundError
from scanproof.evidence.collector import collect_evidence, find_jobs
from scanproof.evidence.models import ScanEvidence
from scanproof.inspection import inspect_pipeline
from scanproof.models import InspectedJob, Pipeline
from scanproof.policy.engine import Decision, RequirementInput, RequirementResult, evaluate
from scanproof.policy.models import Policy, Requirement
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
    attestations: dict[str, list[AttestationEvidence]] = Field(
        default_factory=dict, description="Every bundle checked, per requirement id"
    )
    warnings: list[str] = Field(default_factory=list)


def verify_pipeline(
    connector: CIConnector,
    policy: Policy,
    *,
    instance_url: str,
    project: str,
    pipeline_id: int,
    trust: TrustConfig | None = None,
) -> VerificationReport:
    inspection = inspect_pipeline(
        connector, instance_url=instance_url, project=project, pipeline_id=pipeline_id
    )
    inputs: dict[str, RequirementInput] = {}
    cache: dict[tuple[int, str, str, str | None], ScanEvidence] = {}
    bundle_cache: dict[tuple[str, ...], list[AttestationEvidence]] = {}
    job_ids = {i for j in inspection.jobs for i in j.attempt_ids}
    trust = trust or TrustConfig()

    def attest(req: Requirement, job: InspectedJob, item: RequirementInput) -> RequirementInput:
        spec = req.attestation
        if spec is None:
            return item
        if spec.subject == "image":
            digest = (req.checks.image_digest_must_match or "").removeprefix("sha256:")
        else:
            ev = item.evidence
            digest = ev.report_sha256 if ev is not None and ev.present else None
        if not digest:
            return item  # the engine reports there is nothing to bind to
        if spec.source == "platform":
            key: tuple[str, ...] = ("platform", digest)
            origin = f"{connector.provider} attestations for sha256:{digest[:12]}"
        else:
            bundle_artifact = spec.artifact_name or req.artifact_name
            key = ("artifact", str(job.latest.id), spec.bundle_path or "", bundle_artifact or "")
            origin = spec.bundle_path
        try:
            if key not in bundle_cache:
                if spec.source == "platform":
                    raw = connector.fetch_attestations(project, f"sha256:{digest}")
                else:
                    raw = connector.fetch_report(
                        project, job.latest, spec.bundle_path or "", bundle_artifact
                    )
                bundle_cache[key] = verify_bundles(
                    raw, trust, origin=origin, artifact_sha256=digest
                )
        except NotFoundError:
            bundle_cache[key] = []
        except ConnectorError as exc:
            return item.model_copy(
                update={
                    "attestation_error": f"Could not fetch attestations ({origin}): "
                    f"{exc.kind.value}: {exc.message}"
                }
            )
        checked = []
        for att in bundle_cache[key]:
            uri = att.signer.run_invocation_uri if att.signer else None
            run = connector.run_matches(uri, inspection.pipeline, job_ids) if att.signer else None
            checked.append(att.model_copy(update={"run_matches": run}))
        return item.model_copy(update={"attestations": checked})

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
            return attest(req, job, RequirementInput(job=job, evidence=cache[key]))
        except ConnectorError as exc:
            failed = RequirementInput(
                job=job,
                evidence_error=(
                    f"Could not fetch {req.report_path}: {exc.kind.value}: {exc.message}"
                ),
            )
            return attest(req, job, failed)  # an image attestation doesn't need the report

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

    generated_at = datetime.now(UTC)
    evaluation = evaluate(policy, inspection.pipeline, inputs, now=generated_at)
    evidence: dict[str, ScanEvidence] = {}
    attestations: dict[str, list[AttestationEvidence]] = {}
    for rid, item in inputs.items():
        for key, one in [(rid, item), *((f"{rid} [{n}]", i) for n, i in item.instances or [])]:
            if one.evidence is not None:
                evidence[key] = one.evidence
            if one.attestations:
                attestations[key] = one.attestations
    return VerificationReport(
        scanproof_version=__version__,
        generated_at=generated_at,
        policy=policy.name,
        provider=connector.provider,
        instance_url=instance_url,
        project=project,
        pipeline=inspection.pipeline,
        decision=evaluation.decision,
        exit_code=evaluation.decision.exit_code,
        requirements=evaluation.requirements,
        evidence=evidence,
        attestations=attestations,
        warnings=[*inspection.warnings, *evaluation.warnings],
    )
