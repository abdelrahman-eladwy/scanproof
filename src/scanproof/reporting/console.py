"""Human-readable summary, written to stderr so stdout stays machine-readable JSON."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from scanproof.evidence.models import ScanEvidence
from scanproof.models import InspectionReport, JobStatus

if TYPE_CHECKING:
    from scanproof.verification import VerificationReport

_STATUS_MARK = {
    JobStatus.SUCCESS: "OK  ",
    JobStatus.FAILED: "FAIL",
    JobStatus.CANCELED: "CANC",
    JobStatus.SKIPPED: "SKIP",
    JobStatus.MANUAL: "MAN ",
}


def print_inspection_summary(report: InspectionReport) -> None:
    p = report.pipeline
    out = lambda line="": typer.echo(line, err=True)  # noqa: E731
    out(f"ScanProof {report.scanproof_version} - pipeline inspection")
    out(f"Project:  {report.project}")
    out(f"Pipeline: #{p.id}  status={p.status}  ref={p.ref}  sha={p.sha[:12]}")
    out()
    for job in report.jobs:
        mark = _STATUS_MARK.get(job.latest.status, "??  ")
        flags = []
        if job.latest.allow_failure:
            flags.append("allow_failure")
        if job.attempts > 1:
            flags.append(f"{job.attempts} attempts")
        if job.latest.has_archive:
            flags.append("artifacts")
        suffix = f"  [{', '.join(flags)}]" if flags else ""
        out(f"  [{mark}] {job.stage or '-'}/{job.name}  (job {job.latest.id}){suffix}")
    if report.warnings:
        out()
        out("Warnings:")
        for w in report.warnings:
            out(f"  - {w}")


def _unknown(value: object) -> str:
    return "unknown" if value is None else str(value)


def print_evidence_summary(ev: ScanEvidence) -> None:
    out = lambda line="": typer.echo(line, err=True)  # noqa: E731
    engine = f"  engine={ev.scanner_name}" if ev.scanner_name else ""
    out(f"Evidence: {ev.tool} ({ev.scan_type.value})  version={_unknown(ev.tool_version)}{engine}")
    if not ev.present:
        out(f"  report:   MISSING - {ev.parse_error}")
        return
    if not ev.parseable:
        out(f"  report:   INVALID - {ev.parse_error}")
        return
    out(f"  report:   ok  sha256={ev.report_sha256[:16] if ev.report_sha256 else '-'}")
    files = ev.scope.files_scanned if ev.scope else None
    targets = (
        len(ev.scope.scanned_paths) if ev.scope and ev.scope.scanned_paths is not None else None
    )
    components = ev.scope.components if ev.scope else None
    resources = ev.scope.resources if ev.scope else None
    if components is not None:
        out(f"  scope:    components={components}")
    elif resources is not None:
        out(f"  scope:    resources={resources}")
    else:
        out(f"  scope:    files={_unknown(files)}  targets={_unknown(targets)}")
    out(f"  errors:   {_unknown(ev.scanner_error_count)}")
    if ev.findings is not None:
        sev = ", ".join(f"{k}={v}" for k, v in ev.findings.by_severity.items()) or "none"
        out(f"  findings: {ev.findings.total} ({sev})")
    if ev.target is not None:
        digests = ", ".join(sorted(ev.target.digests())) or "unknown"
        out(f"  target:   {_unknown(ev.target.artifact_name)}  digest={digests}")


def print_verification_summary(report: VerificationReport) -> None:
    out = lambda line="": typer.echo(line, err=True)  # noqa: E731
    p = report.pipeline
    out(f"ScanProof {report.scanproof_version} - verify")
    out(f"Policy:   {report.policy}")
    out(f"Project:  {report.project}")
    out(f"Pipeline: #{p.id}  ref={p.ref}  sha={p.sha[:12]}")
    out()
    for req in report.requirements:
        job = f"job {req.job_id}" if req.job_id else "no job"
        findings = f"  findings={req.findings['total']}" if req.findings else ""
        out(f"[{req.outcome.value:<4}] {req.id}  {req.tool} @ {req.job_name} ({job}){findings}")
        for check in req.checks:
            if check.outcome.value in {"FAIL", "UNKNOWN"}:
                out(f"         {check.outcome.value}: {check.code}: {check.message}")
    if report.warnings:
        out()
        out("Warnings:")
        for w in report.warnings:
            out(f"  - {w}")
    out()
    failed = sum(r.outcome.value == "FAIL" for r in report.requirements)
    unknown = sum(r.outcome.value == "UNKNOWN" for r in report.requirements)
    out(
        f"Decision: {report.decision.value}  "
        f"({failed} failed, {unknown} unknown)  exit {report.exit_code}"
    )
    out("Note: ScanProof verifies scan evidence, not the absence of vulnerabilities.")
