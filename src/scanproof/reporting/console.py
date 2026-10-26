"""Human-readable summary, written to stderr so stdout stays machine-readable JSON."""

from __future__ import annotations

import typer

from scanproof.evidence.models import ScanEvidence
from scanproof.models import InspectionReport, JobStatus

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
    out(f"Evidence: {ev.tool} ({ev.scan_type.value})  version={_unknown(ev.tool_version)}")
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
    out(f"  scope:    files={_unknown(files)}  targets={_unknown(targets)}")
    out(f"  errors:   {_unknown(ev.scanner_error_count)}")
    if ev.findings is not None:
        sev = ", ".join(f"{k}={v}" for k, v in ev.findings.by_severity.items()) or "none"
        out(f"  findings: {ev.findings.total} ({sev})")
    if ev.target is not None:
        digests = ", ".join(sorted(ev.target.digests())) or "unknown"
        out(f"  target:   {_unknown(ev.target.artifact_name)}  digest={digests}")
