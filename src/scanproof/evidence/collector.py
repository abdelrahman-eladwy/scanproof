"""Fetch a job's report from the CI platform and turn it into ScanEvidence.

Missing evidence (job uploaded no artifacts, file not in the archive) is a *fact*
and comes back as `present=False`. Inability to look (auth, network, server) raises
ConnectorError so callers can treat it as UNKNOWN rather than as a missing report.
"""

from __future__ import annotations

from scanproof.connectors.base import AuthError, CIConnector, ConnectorError, NotFoundError
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

    if not job.latest.has_archive:
        evidence = adapter.parse(None)
        evidence.parse_error = "Job uploaded no artifacts archive"
    else:
        try:
            raw = connector.download_artifact_file(project, job.latest.id, report_path)
        except NotFoundError:
            evidence = adapter.parse(None)
            evidence.parse_error = (
                f"'{report_path}' not found in job artifacts (never uploaded, or expired)"
            )
        except AuthError as exc:
            # GitLab 17+ restricts security-scan artifacts (artifacts:access) to Developer+.
            raise AuthError(
                f"{exc.message} Report artifacts may be restricted with artifacts:access; "
                "security scan templates need a Developer-role token.",
                exc.status_code,
            ) from None
        except ConnectorError:
            raise
        else:
            evidence = adapter.parse(raw)

    evidence.source = source
    return evidence


def find_job(jobs: list[InspectedJob], name: str) -> InspectedJob | None:
    return next((j for j in jobs if j.name == name), None)
