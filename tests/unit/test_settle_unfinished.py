"""#118: platform job status can lag completion; re-read within a bounded budget.

Waiting never turns an unfinished job into a pass: after the budget it stays UNKNOWN.
"""

from __future__ import annotations

import httpx
import pytest

from scanproof.connectors.github import GitHubConnector
from scanproof.policy.engine import Decision
from scanproof.policy.models import Policy
from scanproof.verification import SETTLE_FIRST_DELAY, verify_pipeline
from tests.fake_github import API, REPO, RUN, FakeGitHub


@pytest.fixture
def gh(mock_api) -> FakeGitHub:
    return FakeGitHub(mock_api)


@pytest.fixture
def conn(sleeps):
    with GitHubConnector(API, "ghp_test", sleep=sleeps.append, max_retries=1) as client:
        yield client


def policy() -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "github", "id": REPO},
            "requirements": [
                {
                    "id": "SAST",
                    "tool": "semgrep",
                    "job_name": "scan",
                    "artifact_name": "none",
                    "report_path": "none.json",
                    "checks": {"report_required": False},
                }
            ],
        }
    )


def run(gh, conn, *, budget, sleep):
    gh.install()
    # Serve the *current* job list on every read so a test can change it mid-verify.
    gh.router.get(f"{API}/repos/{REPO}/actions/runs/{RUN}/jobs").mock(
        side_effect=lambda _req: httpx.Response(200, json={"jobs": gh.jobs})
    )
    return verify_pipeline(
        conn,
        policy(),
        instance_url=API,
        project=REPO,
        pipeline_id=RUN,
        settle_seconds=budget,
        sleep=sleep,
    )


def codes(report):
    return {c.code for r in report.requirements for c in r.checks}


def test_lagging_queued_status_settles_to_verified(gh, conn):
    gh.job(10, "scan", status="queued", conclusion=None)
    pauses: list[float] = []

    def sleep(seconds: float) -> None:
        pauses.append(seconds)
        gh.jobs[0].update(status="completed", conclusion="success")

    report = run(gh, conn, budget=30, sleep=sleep)
    assert report.decision is Decision.VERIFIED
    assert pauses == [SETTLE_FIRST_DELAY]
    assert any("now finished" in w for w in report.warnings)


def test_still_unfinished_after_budget_stays_indeterminate(gh, conn):
    gh.job(10, "scan", status="in_progress", conclusion=None)
    pauses: list[float] = []
    report = run(gh, conn, budget=30, sleep=pauses.append)
    assert report.decision is Decision.INDETERMINATE
    assert report.exit_code == 2
    assert "JOB_NOT_FINISHED" in codes(report)
    assert sum(pauses) == 30  # 5 + 10 + 15 (capped): never exceeds the budget
    assert pauses == [5.0, 10.0, 15.0]
    assert any("still unfinished" in w for w in report.warnings)


def test_settling_to_a_failure_blocks(gh, conn):
    gh.job(10, "scan", status="queued", conclusion=None)

    def sleep(_: float) -> None:
        gh.jobs[0].update(status="completed", conclusion="failure")

    report = run(gh, conn, budget=30, sleep=sleep)
    assert report.decision is Decision.BLOCKED


def test_zero_budget_never_waits(gh, conn):
    gh.job(10, "scan", status="queued", conclusion=None)
    pauses: list[float] = []
    report = run(gh, conn, budget=0, sleep=pauses.append)
    assert report.decision is Decision.INDETERMINATE
    assert pauses == []
    assert not any("re-read" in w for w in report.warnings)


def test_finished_pipeline_is_not_reread(gh, conn):
    gh.job(10, "scan")
    pauses: list[float] = []
    report = run(gh, conn, budget=30, sleep=pauses.append)
    assert report.decision is Decision.VERIFIED
    assert pauses == []
