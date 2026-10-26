"""Fetch a job's report from the CI platform and turn it into ScanEvidence.

Missing evidence (job uploaded no artifacts, file not in the archive) is a *fact*
and comes back as `present=False`. Inability to look (auth, network, server) raises
ConnectorError so callers can treat it as UNKNOWN rather than as a missing report.
"""

from __future__ import annotations

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
    source = EvidenceSource(
        provider=connector.provider,
        project=project,
        pipeline_id=pipeline.id,
        pipeline_sha=pipeline.sha,
        job_id=job.latest.id,
        job_name=job.name,
        job_commit_sha=job.latest.commit_sha,
        artifact_path=report_path,
    )

    try:
        raw = connector.fetch_report(project, job.latest, report_path, artifact_name)
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
