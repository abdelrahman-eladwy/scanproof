"""Milestone 1: Pipeline Inspector.

Collects what a pipeline actually contains — jobs, their latest attempts, retry
history and artifacts — without applying any policy. Later milestones consume
this output; keeping it judgement-free makes it easy to test and to audit.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from scanproof import __version__
from scanproof.connectors.base import CIConnector, ConnectorError, ErrorKind
from scanproof.models import Downstream, InspectedJob, InspectionReport, Job, JobStatus

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


DOWNSTREAM_SEPARATOR = " > "
MAX_DOWNSTREAM_DEPTH = 3
MAX_DOWNSTREAM_PIPELINES = 50


def _walk_downstream(
    connector: CIConnector, project: str, pipeline_id: int, warnings: list[str]
) -> tuple[list[Job], list[Downstream], list[str]]:
    """Collect jobs from child / multi-project pipelines, breadth first and bounded.

    Downstream jobs are renamed '<trigger> > <job>' so jobs from different children can never
    be mistaken for each other or for retries of a parent job. A downstream pipeline that
    exists but can't be read is recorded, so a job missing from the inventory becomes
    unknown rather than absent.
    """
    jobs: list[Job] = []
    seen: list[Downstream] = []
    unreadable: list[str] = []
    queue: list[tuple[str, int, str, int]] = [(project, pipeline_id, "", 0)]
    visited = {(project, pipeline_id)}
    while queue:
        cur_project, cur_id, prefix, depth = queue.pop(0)
        try:
            bridges = connector.list_downstream(cur_project, cur_id)
        except ConnectorError as exc:
            if depth == 0 and exc.kind is ErrorKind.NOT_FOUND:
                continue  # platform/version without a bridges API for this pipeline
            unreadable.append(f"{prefix or 'pipeline'} triggers ({exc.kind.value})")
            continue
        for bridge in bridges:
            label = f"{prefix}{bridge.trigger_name}"
            seen.append(bridge)
            if bridge.pipeline_id is None or bridge.project is None:
                warnings.append(
                    f"Trigger '{label}' ({bridge.trigger_status.value}) did not start a "
                    "downstream pipeline."
                )
                continue
            key = (bridge.project, bridge.pipeline_id)
            if key in visited:
                continue
            if depth + 1 > MAX_DOWNSTREAM_DEPTH or len(visited) >= MAX_DOWNSTREAM_PIPELINES:
                unreadable.append(f"{label} (beyond depth/count limit)")
                continue
            visited.add(key)
            try:
                child_jobs = connector.list_jobs(bridge.project, bridge.pipeline_id)
            except ConnectorError as exc:
                unreadable.append(f"{label} ({exc.kind.value})")
                warnings.append(
                    f"Downstream pipeline of trigger '{label}' could not be read "
                    f"({exc.kind.value}); jobs in it can't be verified."
                )
                continue
            child_prefix = f"{label}{DOWNSTREAM_SEPARATOR}"
            jobs.extend(
                j.model_copy(update={"name": f"{child_prefix}{j.name}", "project": bridge.project})
                for j in child_jobs
            )
            queue.append((bridge.project, bridge.pipeline_id, child_prefix, depth + 1))
    return jobs, seen, unreadable


def inspect_pipeline(
    connector: CIConnector, *, instance_url: str, project: str, pipeline_id: int
) -> InspectionReport:
    pipeline = connector.get_pipeline(project, pipeline_id)
    jobs = connector.list_jobs(project, pipeline_id)
    warnings: list[str] = []
    child_jobs, downstream, unreadable = _walk_downstream(connector, project, pipeline_id, warnings)
    inspected = group_attempts([*jobs, *child_jobs], pipeline.sha)

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
                f"Job '{job.name}' ended '{job.latest.status.value}' but has allow_failure: true "
                "(or continue-on-error), so the pipeline did not stop on it."
            )
    unchecked = [j.name for j in inspected if j.latest.masking_checked is False]
    if unchecked:
        warnings.append(
            "Could not read check-run annotations (grant checks:read) to rule out steps hidden by "
            f"continue-on-error in: {', '.join(unchecked)}."
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
        downstream=downstream,
        unreadable_downstream=unreadable,
        warnings=warnings,
    )
