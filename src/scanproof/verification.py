"""Milestone 3: `scanproof verify` orchestration.

Gathers inputs (inspection + evidence per requirement) through a connector, then hands
them to the pure policy engine. A connector error while fetching one requirement's
report makes only that requirement UNKNOWN; an error fetching the pipeline itself is
raised to the caller (nothing can be verified).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from scanproof import __version__
from scanproof.attestation.models import AttestationEvidence
from scanproof.attestation.verify import TrustConfig, verify_bundles
from scanproof.connectors.base import CIConnector, ConnectorError, NotFoundError
from scanproof.contracts import VERIFICATION_SCHEMA
from scanproof.evidence.collector import (
    collect_evidence,
    is_qualified,
    match_jobs,
    source_pipeline_of,
)
from scanproof.evidence.models import ScanEvidence
from scanproof.inspection import DOWNSTREAM_SEPARATOR, inspect_pipeline
from scanproof.models import InspectedJob, InspectionReport, Pipeline
from scanproof.policy.engine import Decision, RequirementInput, RequirementResult, evaluate
from scanproof.policy.models import Policy, Requirement
from scanproof.scanners import get_adapter


class ConnectorErrorDetail(BaseModel):
    """Why the CI platform could not be read. Never contains credentials."""

    kind: str = Field(description="connectors.base.ErrorKind value, e.g. AUTH, NETWORK")
    message: str
    status_code: int | None = None


class VerificationErrorReport(BaseModel):
    """Written by `verify -o` when nothing could be verified (exit 2, INDETERMINATE).

    Same schema_version as VerificationReport; consumers tell the two apart by the
    presence of `error` (and absence of `requirements`).
    """

    schema_version: Literal["scanproof.dev/verification/v1alpha1"] = VERIFICATION_SCHEMA
    scanproof_version: str = __version__
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    decision: Literal["INDETERMINATE"] = "INDETERMINATE"
    exit_code: Literal[2] = 2
    project: str
    pipeline_id: int
    error: ConnectorErrorDetail


class VerificationReport(BaseModel):
    schema_version: Literal["scanproof.dev/verification/v1alpha1"] = VERIFICATION_SCHEMA
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


#: First pause before re-reading a pipeline whose required jobs are not finished;
#: doubled each time, capped by the caller's total ``settle_seconds`` budget.
SETTLE_FIRST_DELAY = 5.0


def _has_unfinished(report: VerificationReport) -> bool:
    return any(c.code == "JOB_NOT_FINISHED" for r in report.requirements for c in r.checks)


def verify_pipeline(
    connector: CIConnector,
    policy: Policy,
    *,
    instance_url: str,
    project: str,
    pipeline_id: int,
    trust: TrustConfig | None = None,
    settle_seconds: float = 0,
    sleep: Callable[[float], None] = time.sleep,
) -> VerificationReport:
    """Verify a pipeline; optionally re-read it while required jobs look unfinished.

    CI platforms can report a job as queued/running after it finished (GitHub under
    load, even for a gate that `needs:` the job: #118). With ``settle_seconds > 0`` the
    whole verification is repeated with backoff until no requirement reports
    JOB_NOT_FINISHED or the budget is spent. Only the last result is returned, so an
    unfinished job after the budget is still UNKNOWN: nothing is assumed from waiting.
    """
    report = _verify_once(
        connector,
        policy,
        instance_url=instance_url,
        project=project,
        pipeline_id=pipeline_id,
        trust=trust,
    )
    waited, delay, rereads = 0.0, SETTLE_FIRST_DELAY, 0
    while _has_unfinished(report) and waited < settle_seconds:
        pause = min(delay, settle_seconds - waited)
        sleep(pause)
        waited, delay, rereads = waited + pause, delay * 2, rereads + 1
        report = _verify_once(
            connector,
            policy,
            instance_url=instance_url,
            project=project,
            pipeline_id=pipeline_id,
            trust=trust,
        )
    if rereads:
        state = "still unfinished" if _has_unfinished(report) else "now finished"
        report = report.model_copy(
            update={
                "warnings": [
                    *report.warnings,
                    f"Required jobs were reported unfinished; re-read the pipeline {rereads} "
                    f"time(s) over {waited:g}s and they are {state}.",
                ]
            }
        )
    return report


def _absence_unknown(inspection: InspectionReport, name: str, *, bounded: bool) -> str | None:
    if not inspection.unreadable_downstream:
        return None
    reasons = inspection.unreadable_downstream
    if bounded and inspection.unreadable_scopes:
        reasons = []
        for scope in inspection.unreadable_scopes:
            prefix = f"{scope.path}{DOWNSTREAM_SEPARATOR}" if scope.path else ""
            if not name.startswith(prefix):
                continue
            tail = name[len(prefix) :]
            if not scope.triggers_only or DOWNSTREAM_SEPARATOR in tail:
                reasons.append(scope.reason)
    return f"these pipelines could not be read: {', '.join(reasons)}" if reasons else None



def _verify_once(
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
    cache: dict[tuple[str, int, int, str, str, str | None], ScanEvidence] = {}
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
        source_project = job.latest.project or project
        if spec.source == "platform":
            key: tuple[str, ...] = ("platform", source_project, digest)
            origin = f"{connector.provider} attestations for sha256:{digest[:12]}"
        else:
            bundle_artifact = spec.artifact_name or req.artifact_name
            key = (
                "artifact",
                source_project,
                str(source_pipeline_of(job, inspection.pipeline)),
                str(job.latest.id),
                spec.bundle_path or "",
                bundle_artifact or "",
            )
            origin = spec.bundle_path
        try:
            if key not in bundle_cache:
                if spec.source == "platform":
                    raw = connector.fetch_attestations(source_project, f"sha256:{digest}")
                else:
                    raw = connector.fetch_report(
                        source_project, job.latest, spec.bundle_path or "", bundle_artifact
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
        key = (
            job.latest.project or project,
            source_pipeline_of(job, inspection.pipeline),
            job.latest.id,
            req.report_path,
            req.tool.lower(),
            req.artifact_name,
        )
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
        match = match_jobs(inspection.jobs, req.job_name, req.instances, req.copies)
        matches, missing = match.jobs, match.missing
        undeclared = {
            "undeclared_instances": match.undeclared_legs or None,
            "undeclared_copies": match.undeclared_copies or None,
        }
        unread = (
            f"these pipelines could not be read: {', '.join(unreadable)}" if unreadable else None
        )
        if unread and matches and not req.copies and not is_qualified(req.job_name):
            undeclared["copies_unbounded"] = unread
        if not matches and not req.copies:
            unknown = _absence_unknown(inspection, req.job_name, bounded=is_qualified(req.job_name))
            inputs[req.id] = RequirementInput(absence_unknown=unknown)
        elif (
            len(matches) == 1
            and not missing
            and not match.missing_declared
            and not match.missing_copies
        ):
            single = collect(req, matches[0])
            inputs[req.id] = single.model_copy(update=undeclared)
        else:
            # Declared copies are judged one by one even when none ran: a copy that is provably
            # absent must FAIL even if another declared copy may sit in an unreadable pipeline.
            instances = [(job.name, collect(req, job)) for job in matches]
            instances += [(name, RequirementInput()) for name in missing]
            instances += [
                (name, RequirementInput(declared_instance=label))
                for name, label in match.missing_declared
            ]
            instances += [
                (
                    name,
                    RequirementInput(
                        missing_copy=path, absence_unknown=_absence_unknown(inspection, name, bounded=True)
                    ),
                )
                for name, path in match.missing_copies
            ]
            inputs[req.id] = RequirementInput(instances=instances, **undeclared)

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
