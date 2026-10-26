"""Human-readable summary, written to stderr so stdout stays machine-readable JSON."""

from __future__ import annotations

import typer

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
