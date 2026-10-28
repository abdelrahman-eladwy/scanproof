"""#62: qualified job names must cover only their own parallel/matrix legs.

The original bug falsely BLOCKED an existing scan in a named child. A fix must
also avoid widening to another child (which could conceal a failing scan).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from scanproof.evidence.collector import match_jobs
from scanproof.models import InspectedJob, Job, JobStatus
from scanproof.policy.engine import Decision, Outcome
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.conftest import BASE, FIXTURES
from tests.fake_gitlab import FakeGitLab

REPORT = {"semgrep.json": (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()}
QUALIFIED = "platform > security > semgrep-sast"


def make_policy(
    *, job_name: str = QUALIFIED, instances: list[str] | None = None, profile: str = "compatible"
) -> Policy:
    requirement = {
        "id": "SAST",
        "tool": "semgrep",
        "job_name": job_name,
        "report_path": "semgrep.json",
        "checks": {"scanner_errors_allowed": 0, "minimum_scanned_files": 1},
    }
    if instances is not None:
        requirement["instances"] = instances
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": "123"},
            "assurance": {"profile": profile},
            "requirements": [requirement],
        }
    )


def verify(connector, gl: FakeGitLab, *, instances=None, profile="compatible"):
    gl.install()
    return verify_pipeline(
        connector,
        make_policy(instances=instances, profile=profile),
        instance_url=BASE,
        project="123",
        pipeline_id=1042,
    )


def codes(report) -> dict[str, str]:
    return {
        check.check: check.code
        for check in report.requirements[0].checks
        if check.outcome not in (Outcome.PASS, Outcome.NOT_APPLICABLE)
    }


def nested(gl: FakeGitLab):
    return gl.child("platform", pipeline_id=2000).child("security", pipeline_id=3000)


def test_qualified_parallel_all_legs_pass_and_foreign_jobs_do_not_count(connector, mock_api):
    gl = FakeGitLab(mock_api)
    child = nested(gl)
    for idx in (1, 2, 3):
        child.job(3000 + idx, f"semgrep-sast {idx}/3", files=REPORT)
    gl.job(10, "semgrep-sast 1/3", status="failed", files=REPORT)
    gl.child("other", pipeline_id=4000).job(4001, "semgrep-sast 1/3", status="failed", files=REPORT)
    result = verify(connector, gl)
    assert result.decision is Decision.VERIFIED
    assert sorted(result.requirements[0].instances) == [f"{QUALIFIED} {idx}/3" for idx in (1, 2, 3)]


def test_qualified_parallel_missing_index_cannot_be_hidden_by_other_child(connector, mock_api):
    gl = FakeGitLab(mock_api)
    child = nested(gl)
    child.job(3001, "semgrep-sast 1/3", files=REPORT)
    child.job(3003, "semgrep-sast 3/3", files=REPORT)
    gl.child("other", pipeline_id=4000).job(4002, "semgrep-sast 2/3", files=REPORT)
    result = verify(connector, gl)
    assert result.decision is Decision.BLOCKED
    assert codes(result) == {f"job_present [{QUALIFIED} 2/3]": "REQUIRED_JOB_ABSENT"}


@pytest.mark.parametrize(
    "legs",
    [
        ("semgrep-sast: [py]", "semgrep-sast: [go]"),
        ("semgrep-sast (py)", "semgrep-sast (go)"),
    ],
    ids=["gitlab-matrix", "github-style-matrix"],
)
def test_qualified_matrix_evaluates_every_leg(connector, mock_api, legs):
    gl = FakeGitLab(mock_api)
    child = nested(gl)
    child.job(3001, legs[0], files=REPORT)
    child.job(3002, legs[1], status="failed", files=REPORT)
    gl.child("other", pipeline_id=4000).job(4001, legs[0], files=REPORT)
    result = verify(connector, gl)
    assert result.decision is Decision.BLOCKED
    assert codes(result) == {f"job_success [platform > security > {legs[1]}]": "JOB_NOT_SUCCESS"}


def test_qualified_declared_matrix_missing_leg_blocks(connector, mock_api):
    gl = FakeGitLab(mock_api)
    nested(gl).job(3001, "semgrep-sast: [py]", files=REPORT)
    gl.child("other", pipeline_id=4000).job(4001, "semgrep-sast: [go]", files=REPORT)
    result = verify(connector, gl, instances=["py", "go"], profile="production")
    assert result.decision is Decision.BLOCKED
    assert codes(result) == {f"job_present [{QUALIFIED}: [go]]": "REQUIRED_INSTANCE_ABSENT"}


def test_qualified_production_job_does_not_need_copies_declaration(connector, mock_api):
    gl = FakeGitLab(mock_api)
    nested(gl).job(3001, "semgrep-sast: [py]", files=REPORT)
    result = verify(connector, gl, instances=["py"], profile="production")
    assert result.decision is Decision.VERIFIED
    assert "copies_declared" not in [c.check for c in result.requirements[0].checks]


def test_qualified_missing_report_still_blocks(connector, mock_api):
    gl = FakeGitLab(mock_api)
    child = nested(gl)
    child.job(3001, "semgrep-sast (py)", files=REPORT)
    child.job(3002, "semgrep-sast (go)", files={})
    result = verify(connector, gl)
    assert result.decision is Decision.BLOCKED
    assert codes(result) == {f"report [{QUALIFIED} (go)]": "REPORT_MISSING"}


def test_qualified_reusable_workflow_scope_and_declared_github_legs():
    def item(num: int, name: str) -> InspectedJob:
        latest = Job(
            id=num,
            name=name,
            status=JobStatus.SUCCESS,
            commit_sha="a" * 40,
            finished_at=datetime(2026, 10, 28, tzinfo=UTC),
        )
        return InspectedJob(
            name=name,
            stage=None,
            latest=latest,
            attempt_ids=[num],
            commit_matches_pipeline=True,
        )

    jobs = [
        item(1, "api / sast (py)"),
        item(2, "web / sast (go)"),
        item(3, "api / sast (extra)"),
        item(4, "sast (go)"),
    ]
    match = match_jobs(jobs, "api / sast", instances=["py", "go"])
    assert [x.name for x in match.jobs] == ["api / sast (py)", "api / sast (extra)"]
    assert match.missing_declared == [("api / sast (go)", "go")]
    assert match.undeclared_copies == []
    assert match_jobs(jobs, "sast").jobs == jobs  # unqualified behavior unchanged
