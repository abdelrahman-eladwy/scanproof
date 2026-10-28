"""#90: rerunning only the gate must not make old masked GitHub jobs VERIFIED.

GitHub's jobs?filter=all returns synthetic attempt-2 entries for scans that
actually ran before the attempt-2 start. Their new check-run annotations can
be empty even when the original step failed under continue-on-error.
"""

from __future__ import annotations

import pytest

from scanproof.connectors.github import GitHubConnector
from scanproof.policy.engine import Decision, Outcome
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.fake_github import API, EXIT1, REPO, RUN, FakeGitHub

RUN_START = "2026-10-28T12:48:38Z"
PREVIOUS = "2026-10-28T10:47:46Z"
CURRENT = "2026-10-28T12:48:45Z"


@pytest.fixture
def gh(mock_api) -> FakeGitHub:
    fake = FakeGitHub(mock_api, run_attempt=2, run_conclusion="failure")
    fake.run_started_at = RUN_START
    return fake


@pytest.fixture
def conn(sleeps):
    with GitHubConnector(API, "ghp_test", sleep=sleeps.append, max_retries=1) as client:
        yield client


def policy(job_name: str = "scan") -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "github", "id": REPO},
            "requirements": [
                {
                    "id": "SAST",
                    "tool": "semgrep",
                    "job_name": job_name,
                    "artifact_name": "none",
                    "report_path": "none.json",
                    "checks": {"report_required": False},
                }
            ],
        }
    )


def decide(gh: FakeGitHub, conn, *, name: str = "scan"):
    gh.install()
    return verify_pipeline(
        conn, policy(name), instance_url=API, project=REPO, pipeline_id=RUN
    )


def test_gate_only_rerun_does_not_verify_old_masked_scan(gh, conn):
    # This reproduces real GitHub attempt-2 metadata: old annotation is visible in
    # attempt 1, but the synthesized attempt-2 check-run returned an empty list.
    gh.job(10, "scan", attempt=1, started_at=PREVIOUS, notes=[[EXIT1]])
    gh.job(20, "scan", attempt=2, started_at=PREVIOUS, notes=[[]])
    result = decide(gh, conn)
    assert result.decision is Decision.INDETERMINATE
    assert result.exit_code == 2
    checks = result.requirements[0].checks
    assert any(
        c.code == "STEP_MASKING_UNKNOWN" and c.outcome is Outcome.UNKNOWN for c in checks
    )


def test_current_attempt_scanner_with_readable_annotations_is_verified(gh, conn):
    gh.job(20, "scan", attempt=2, started_at=CURRENT, notes=[[]])
    assert decide(gh, conn).decision is Decision.VERIFIED


def test_current_attempt_masked_failure_still_blocks(gh, conn):
    gh.job(20, "scan", attempt=2, started_at=CURRENT, notes=[[EXIT1]])
    result = decide(gh, conn)
    assert result.decision is Decision.BLOCKED
    assert any(c.code == "FAILURE_MASKED_BY_ALLOW_FAILURE" for c in result.requirements[0].checks)


@pytest.mark.parametrize("started", [None, "not-a-timestamp", PREVIOUS])
def test_missing_invalid_or_prior_start_does_not_silently_verify(gh, conn, started):
    gh.job(20, "scan", attempt=2, started_at=started, notes=[[]])
    assert decide(gh, conn).decision is Decision.INDETERMINATE


def test_job_from_old_attempt_is_unknown_even_without_synthetic_copy(gh, conn):
    gh.job(10, "scan", attempt=1, started_at=PREVIOUS, notes=[[]])
    assert decide(gh, conn).decision is Decision.INDETERMINATE


def test_run_attempt_one_maintains_original_behavior(mock_api, conn):
    gh = FakeGitHub(mock_api, run_attempt=1, run_conclusion="success")
    gh.job(10, "scan", attempt=1, started_at=None, notes=[[]])
    assert decide(gh, conn).decision is Decision.VERIFIED
