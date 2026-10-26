"""Milestone 1: Pipeline Inspector.

Collects what a pipeline actually contains — jobs, their latest attempts, retry
history and artifacts — without applying any policy. Later milestones consume
this output; keeping it judgement-free makes it easy to test and to audit.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from scanproof import __version__
from scanproof.connectors.base import CIConnector
from scanproof.models import InspectedJob, InspectionReport, Job, JobStatus

_MASKABLE = frozenset({JobStatus.FAILED, JobStatus.CANCELED})


def group_attempts(jobs: list[Job], pipeline_sha: str) -> list[InspectedJob]:
    """Collapse retries: the attempt with the highest id is the effective one."""
    by_name: dict[str, list[Job]] = defaultdict(list)
    for job in jobs:
        by_name[job.name].append(job)

    inspected: list[InspectedJob] = []
    for name, attempts in by_name.items():
        attempts.sort(key=lambda j: j.id)
        latest = attempts[-1]
        matches = None if latest.commit_sha is None else latest.commit_sha == pipeline_sha
        inspected.append(
            InspectedJob(
                name=name,
                stage=latest.stage,
                latest=latest,
                attempt_ids=[j.id for j in attempts],
                commit_matches_pipeline=matches,
            )
        )
    return sorted(inspected, key=lambda j: (j.stage or "", j.name))


def inspect_pipeline(
    connector: CIConnector, *, instance_url: str, project: str, pipeline_id: int
) -> InspectionReport:
    pipeline = connector.get_pipeline(project, pipeline_id)
    jobs = connector.list_jobs(project, pipeline_id)
    inspected = group_attempts(jobs, pipeline.sha)

    warnings: list[str] = []
    if pipeline.status in {"created", "pending", "running", "waiting_for_resource", "preparing"}:
        warnings.append(
            f"Pipeline is still '{pipeline.status}'; job states and artifacts may change."
        )
    for job in inspected:
        if job.commit_matches_pipeline is False:
            warnings.append(
                f"Job '{job.name}' reports commit {job.latest.commit_sha} "
                f"but the pipeline is for {pipeline.sha}."
            )
        if job.attempts > 1:
            warnings.append(f"Job '{job.name}' was retried ({job.attempts} attempts).")
        # Manual jobs are allow_failure by default in GitLab; only real failures are masked.
        if job.latest.allow_failure and job.latest.status in _MASKABLE:
            warnings.append(
                f"Job '{job.name}' ended '{job.latest.status.value}' but has allow_failure: true, "
                "so the pipeline did not stop on it."
            )
    if not inspected:
        warnings.append("Pipeline has no jobs visible to this token.")

    return InspectionReport(
        scanproof_version=__version__,
        generated_at=datetime.now(UTC),
        provider=connector.provider,
        instance_url=instance_url,
        project=project,
        pipeline=pipeline,
        jobs=inspected,
        warnings=warnings,
    )
