"""#88: unbounded parallel totals must never bypass the missing-leg invariant.

Reproduces a false VERIFIED when a provider says "sast 1/1001" and reports
nothing about the other 1,000 legs. The previous enumerator silently skipped
groups whose reported total exceeded 1,000 to avoid allocating huge lists.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from scanproof.evidence.collector import match_jobs
from scanproof.models import InspectedJob, Job, JobStatus
from scanproof.policy.engine import Decision
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.conftest import BASE, FIXTURES
from tests.fake_gitlab import FakeGitLab

REPORT = {"semgrep.json": (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()}
SHA = "a" * 40


def _policy():
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": "123"},
            "requirements": [
                {
                    "id": "SAST",
                    "tool": "semgrep",
                    "job_name": "semgrep-sast",
                    "report_path": "semgrep.json",
                    "checks": {"scanner_errors_allowed": 0, "minimum_scanned_files": 1},
                }
            ],
        }
    )


def _inspected(i: int, name: str | None = None) -> InspectedJob:
    name = name or f"semgrep-sast {i}/1001"
    j = Job(
        id=i + 10000,
        name=name,
        status=JobStatus.SUCCESS,
        commit_sha=SHA,
        finished_at=datetime(2026, 10, 28, tzinfo=UTC),
    )
    return InspectedJob(
        name=name,
        stage=None,
        latest=j,
        attempt_ids=[j.id],
        commit_matches_pipeline=True,
    )


def test_large_declared_parallel_total_with_one_leg_never_verifies(connector, mock_api):
    """Security regression: 1/1001 is evidence that 1,000 required legs are absent."""
    gl = FakeGitLab(mock_api)
    gl.job(1, "semgrep-sast 1/1001", files=REPORT)
    gl.install()
    report = verify_pipeline(
        connector,
        _policy(),
        instance_url=BASE,
        project="123",
        pipeline_id=1042,
    )
    assert report.decision is Decision.BLOCKED
    assert any(c.code == "REQUIRED_JOB_ABSENT" for c in report.requirements[0].checks)


def test_large_parallel_all_present_is_allowed_without_enumeration():
    match = match_jobs([_inspected(i) for i in range(1, 1002)], "semgrep-sast")
    assert len(match.jobs) == 1001
    assert match.missing == []


def test_large_parallel_missing_middle_index_is_bounded_and_blocking():
    jobs = [_inspected(i) for i in range(1, 1002) if i != 777]
    match = match_jobs(jobs, "semgrep-sast")
    assert len(match.missing) == 1
    assert len(match.missing[0]) < 180


@pytest.mark.parametrize(
    "names",
    [
        ["semgrep-sast 0/2", "semgrep-sast 1/2", "semgrep-sast 2/2"],
        ["semgrep-sast 1/0"],
        ["semgrep-sast 1/2", "semgrep-sast 2/2", "semgrep-sast 3/2"],
        ["semgrep-sast 1/2", "semgrep-sast 2/3"],
        ["semgrep-sast 1/1", "semgrep-sast 1/2", "semgrep-sast 2/2"],
    ],
)
def test_impossible_or_conflicting_parallel_metadata_fails_closed(names):
    assert match_jobs([_inspected(i, name) for i, name in enumerate(names)], "semgrep-sast").missing


def test_absurd_parallel_total_has_compact_diagnostic_not_value_error():
    # 5000 digits would cause Python's int() decimal conversion guard to throw.
    bad = f"semgrep-sast 1/{'9' * 5000}"
    result = match_jobs([_inspected(1, bad)], "semgrep-sast")
    assert len(result.missing) == 1
    assert len(result.missing[0]) < 180


def test_small_parallel_totals_keep_specific_missing_name():
    match = match_jobs(
        [_inspected(1, "semgrep-sast 1/3"), _inspected(3, "semgrep-sast 3/3")],
        "semgrep-sast",
    )
    assert match.missing == ["semgrep-sast 2/3"]


def test_qualified_parallel_total_above_cap_is_not_exempt():
    match = match_jobs(
        [_inspected(1, "platform > security > semgrep-sast 1/1001")],
        "platform > security > semgrep-sast",
    )
    assert match.missing
