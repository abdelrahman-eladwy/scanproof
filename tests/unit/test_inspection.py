from __future__ import annotations

from datetime import UTC, datetime

import httpx

from scanproof.inspection import group_attempts, inspect_pipeline
from scanproof.models import Job, JobStatus
from tests.conftest import API, BASE, load_fixture

SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334"


def _job(id: int, name: str, status: str = "success", sha: str | None = SHA, **kw) -> Job:
    return Job(id=id, name=name, status=JobStatus(status), commit_sha=sha, stage="security", **kw)


def test_latest_attempt_wins() -> None:
    jobs = [_job(10, "trivy-image", "failed"), _job(30, "trivy-image"), _job(20, "semgrep-sast")]
    grouped = {g.name: g for g in group_attempts(jobs, SHA)}

    assert grouped["trivy-image"].latest.id == 30
    assert grouped["trivy-image"].attempt_ids == [10, 30]
    assert grouped["trivy-image"].attempts == 2
    assert grouped["semgrep-sast"].attempts == 1


def test_latest_attempt_is_chosen_by_attempt_number_not_id() -> None:
    """Azure derives job ids from timeline GUIDs, so id order is not chronological.

    A re-run that went success -> failure used to be judged on the successful stale record
    whenever its hash happened to be larger, i.e. a failed control could be VERIFIED.
    """
    stale = _job(9_000_000, "trivy-image", "success", attempt=1)
    current = _job(7_000_000, "trivy-image", "failed", attempt=2)
    grouped = {g.name: g for g in group_attempts([stale, current], SHA)}

    assert grouped["trivy-image"].latest.id == 7_000_000
    assert grouped["trivy-image"].latest.status is JobStatus.FAILED


def test_start_time_breaks_ties_when_attempt_number_is_missing() -> None:
    older = _job(99, "sast", started_at=datetime(2026, 1, 1, 10, 0, tzinfo=UTC))
    newer = _job(1, "sast", started_at=datetime(2026, 1, 1, 11, 0, tzinfo=UTC))
    grouped = {g.name: g for g in group_attempts([older, newer], SHA)}

    assert grouped["sast"].latest.id == 1


def test_commit_binding() -> None:
    grouped = {
        g.name: g
        for g in group_attempts(
            [_job(1, "match"), _job(2, "other", sha="deadbeef"), _job(3, "nosha", sha=None)], SHA
        )
    }
    assert grouped["match"].commit_matches_pipeline is True
    assert grouped["other"].commit_matches_pipeline is False
    assert grouped["nosha"].commit_matches_pipeline is None  # unknown, not assumed


def test_empty_commit_is_unknown_not_a_match() -> None:
    """Two empty SHAs used to compare equal, so same_commit passed on no commit at all."""
    grouped = {g.name: g for g in group_attempts([_job(1, "sast", sha="")], "")}
    assert grouped["sast"].commit_matches_pipeline is None


def test_commit_comparison_ignores_case() -> None:
    grouped = {g.name: g for g in group_attempts([_job(1, "sast", sha=SHA.upper())], SHA)}
    assert grouped["sast"].commit_matches_pipeline is True


def _mock_pipeline(mock_api, pipeline_overrides=None, jobs=None) -> None:
    pipeline = {**load_fixture("gitlab/pipeline.json"), **(pipeline_overrides or {})}
    mock_api.get(f"{API}/projects/123/pipelines/1042").respond(json=pipeline)
    if jobs is None:
        mock_api.get(f"{API}/projects/123/pipelines/1042/jobs").side_effect = [
            httpx.Response(
                200, json=load_fixture("gitlab/jobs_page1.json"), headers={"x-next-page": "2"}
            ),
            httpx.Response(200, json=load_fixture("gitlab/jobs_page2.json")),
        ]
    else:
        mock_api.get(f"{API}/projects/123/pipelines/1042/jobs").respond(json=jobs)


def test_inspect_pipeline_end_to_end(connector, mock_api) -> None:
    _mock_pipeline(mock_api)
    report = inspect_pipeline(connector, instance_url=BASE, project="123", pipeline_id=1042)

    names = [j.name for j in report.jobs]
    assert names == ["deploy-prod", "dependency-check", "semgrep-sast", "trivy-image"]
    trivy = next(j for j in report.jobs if j.name == "trivy-image")
    assert trivy.latest.status is JobStatus.SUCCESS and trivy.attempt_ids == [8822, 8830]

    joined = " ".join(report.warnings)
    assert "'trivy-image' was retried" in joined
    assert "'dependency-check' ended 'failed', but allow_failure" in joined
    # manual jobs are allow_failure by default in GitLab: not a masked failure
    assert "deploy-prod" not in joined
    assert report.schema_version.startswith("scanproof.dev/inspection/")


def test_warns_when_pipeline_still_running(connector, mock_api) -> None:
    _mock_pipeline(mock_api, {"status": "running"}, jobs=[])
    report = inspect_pipeline(connector, instance_url=BASE, project="123", pipeline_id=1042)
    assert any("still 'running'" in w for w in report.warnings)
    assert any("no jobs visible" in w for w in report.warnings)
