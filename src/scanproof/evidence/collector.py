"""Fetch a job's report from the CI platform and turn it into ScanEvidence.

Missing evidence (job uploaded no artifacts, file not in the archive) is a *fact*
and comes back as `present=False`. Inability to look (auth, network, server) raises
ConnectorError so callers can treat it as UNKNOWN rather than as a missing report.
"""

from __future__ import annotations

import re

from scanproof.connectors.base import (
    AuthError,
    CIConnector,
    ConnectorError,
    ErrorKind,
    NotFoundError,
)
from scanproof.evidence.models import EvidenceSource, ScanEvidence
from scanproof.models import InspectedJob, Pipeline
from scanproof.scanners.base import ScannerAdapter


def collect_evidence(
    connector: CIConnector,
    *,
    project: str,
    pipeline: Pipeline,
    job: InspectedJob,
    report_path: str,
    adapter: ScannerAdapter,
    artifact_name: str | None = None,
) -> ScanEvidence:
    # A downstream job's artifacts belong to its own project/pipeline, not to the
    # parent pipeline passed to verify_pipeline(). The job metadata was populated
    # while walking the downstream graph in inspect_pipeline().
    source_project = job.latest.project or project
    source_pipeline_id = (
        job.latest.pipeline_id if job.latest.pipeline_id is not None else pipeline.id
    )
    source_sha = job.latest.commit_sha if job.latest.project else pipeline.sha
    source = EvidenceSource(
        provider=connector.provider,
        project=source_project,
        pipeline_id=source_pipeline_id,
        pipeline_sha=source_sha,
        job_id=job.latest.id,
        job_name=job.name,
        job_commit_sha=job.latest.commit_sha,
        artifact_path=report_path,
    )

    try:
        raw = connector.fetch_report(source_project, job.latest, report_path, artifact_name)
    except NotFoundError as exc:
        evidence = adapter.parse(None)
        evidence.parse_error = exc.message
    except AuthError as exc:
        # GitLab 17+ restricts security-scan artifacts (artifacts:access) to Developer+.
        raise AuthError(
            f"{exc.message} Report artifacts may be restricted with artifacts:access; "
            "security scan templates need a Developer-role token.",
            exc.status_code,
        ) from None
    except ConnectorError as exc:
        if exc.kind is not ErrorKind.INTEGRITY:
            raise
        # The platform recorded a digest and the bytes don't match: tampered or corrupt.
        evidence = adapter.parse(b"")
        evidence.parse_error = exc.message
    else:
        evidence = adapter.parse(raw)

    evidence.source = source
    return evidence


def find_job(jobs: list[InspectedJob], name: str) -> InspectedJob | None:
    return next((j for j in jobs if j.name == name), None)


_PARALLEL = re.compile(r"^(?P<base>.+) (?P<index>\d+)/(?P<total>\d+)$")
_TAIL_SEPARATORS = (" > ", " / ")  # ScanProof downstream prefix; GitHub reusable workflows


def _tail(job_name: str) -> tuple[str, str]:
    """Split 'trigger > child' / 'caller / callee' into (prefix, last segment)."""
    cut = max(job_name.rfind(sep) + len(sep) if sep in job_name else 0 for sep in _TAIL_SEPARATORS)
    return job_name[:cut], job_name[cut:]


def _is_instance(tail: str, name: str) -> bool:
    if tail == name:
        return True
    m = _PARALLEL.match(tail)
    if m and m.group("base") == name:
        return True
    return (tail.startswith(f"{name}: [") and tail.endswith("]")) or (
        tail.startswith(f"{name} (") and tail.endswith(")")
    )


def find_jobs(jobs: list[InspectedJob], name: str) -> tuple[list[InspectedJob], list[str]]:
    """All jobs a requirement's job_name covers, and expected instances that are missing.

    Every job the name covers counts and every one must pass: the exact name itself, parallel
    ('sast 2/3'), GitLab matrix ('sast: [py]'), GitHub matrix ('sast (py)'), downstream
    ('trigger > sast') and GitHub reusable workflow ('caller / sast') jobs. GitLab parallel
    names carry the total, so missing indices are reported.

    An exact match does not hide instances (#59). ScanProof cannot tell a deliberate,
    unrelated 'sast 1/2' from a leg of 'sast', and letting a passing 'sast' stand in for a
    failing leg would be a false VERIFIED. A qualified name ('child > sast') still matches
    only itself, because the instance patterns apply to the last segment.
    """
    matches = [j for j in jobs if j.name == name or _is_instance(_tail(j.name)[1], name)]
    present: dict[tuple[str, int], set[int]] = {}
    for j in matches:
        prefix, tail = _tail(j.name)
        m = _PARALLEL.match(tail)
        if m and m.group("base") == name:
            present.setdefault((prefix, int(m.group("total"))), set()).add(int(m.group("index")))
    missing = [
        f"{prefix}{name} {i}/{total}"
        for (prefix, total), indices in sorted(present.items())
        if total <= 1000
        for i in range(1, total + 1)
        if i not in indices
    ]
    return matches, missing
