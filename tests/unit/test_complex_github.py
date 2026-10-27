"""Complex GitHub Actions scenarios: matrix and reusable-workflow jobs, re-run attempts,
duplicate artifact names, many annotation pages and partial permission failures.
Shapes follow the real API responses in tests/fixtures/github-real/."""

from __future__ import annotations

import pytest

from scanproof.connectors.github import MAX_ANNOTATION_PAGES, GitHubConnector
from scanproof.policy.engine import Decision, Outcome
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.conftest import FIXTURES
from tests.fake_github import API, EXIT1, REPO, RUN, FakeGitHub

SEMGREP = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()


@pytest.fixture
def gh(mock_api) -> FakeGitHub:
    return FakeGitHub(mock_api)


@pytest.fixture
def conn(sleeps):
    with GitHubConnector(API, "ghp_test", sleep=sleeps.append, max_retries=1) as c:
        yield c


def policy(job: str, *, artifact="scan-report", report="semgrep.json", **checks) -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "github", "id": REPO},
            "requirements": [
                {
                    "id": "SAST",
                    "tool": "semgrep",
                    "job_name": job,
                    "artifact_name": artifact,
                    "report_path": report,
                    "checks": checks,
                }
            ],
        }
    )


def verify(conn, gh: FakeGitHub, pol: Policy):
    gh.install()
    return verify_pipeline(conn, pol, instance_url=API, project=REPO, pipeline_id=RUN)


def failing(report) -> dict[str, str]:
    return {c.check: c.code for c in report.requirements[0].checks if c.outcome is not Outcome.PASS}


# ---------------------------------------------------------------- annotations


def test_masked_failure_on_a_later_annotation_page_is_found(conn, gh) -> None:
    """Only page 1 used to be read, so this job looked clean -> VERIFIED.

    Live run 40382339477: GitHub kept 10 of 150 warnings for one step (it caps annotations
    per step and per job), so on github.com today the failure fits on page 1. Pagination is
    defence in depth for GHES and for limits changing; it must not fail open either way."""
    lint = [{"annotation_level": "warning", "message": f"lint {i}"} for i in range(100)]
    gh.job(1, "sast", notes=[lint, lint, [EXIT1]])
    gh.artifact(10, "scan-report", {"semgrep.json": SEMGREP})
    report = verify(conn, gh, policy("sast"))
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {"job_success": "FAILURE_MASKED_BY_ALLOW_FAILURE"}


def test_too_many_annotation_pages_is_unknown_not_clean(conn, gh) -> None:
    lint = [{"annotation_level": "notice", "message": "x"}]
    gh.job(1, "sast", notes=[lint] * (MAX_ANNOTATION_PAGES + 2))
    gh.artifact(10, "scan-report", {"semgrep.json": SEMGREP})
    report = verify(conn, gh, policy("sast"))
    assert report.decision is Decision.INDETERMINATE
    assert failing(report) == {"job_success": "STEP_MASKING_UNKNOWN"}


def test_permission_lost_on_annotation_page_2_is_unknown(conn, gh) -> None:
    gh.job(1, "sast", notes=[[{"annotation_level": "warning", "message": "w"}], 403])
    gh.artifact(10, "scan-report", {"semgrep.json": SEMGREP})
    assert verify(conn, gh, policy("sast")).decision is Decision.INDETERMINATE


# ---------------------------------------------------------------- matrix / reusable


def test_matrix_one_instance_masked(conn, gh) -> None:
    gh.job(1, "sast (python)")
    gh.job(2, "sast (go)", notes=[[EXIT1]])
    gh.artifact(10, "scan-report", {"semgrep.json": SEMGREP})
    report = verify(conn, gh, policy("sast"))
    assert report.decision is Decision.BLOCKED
    assert report.requirements[0].instances == ["sast (go)", "sast (python)"]
    assert failing(report) == {"job_success [sast (go)]": "FAILURE_MASKED_BY_ALLOW_FAILURE"}


def test_reusable_workflow_job_is_matched_by_its_own_name(conn, gh) -> None:
    gh.job(1, "security / sast")
    gh.artifact(10, "scan-report", {"semgrep.json": SEMGREP})
    report = verify(conn, gh, policy("sast"))
    assert report.decision is Decision.VERIFIED


# ---------------------------------------------------------------- re-runs and artifacts


def test_rerun_attempt_two_succeeds(conn, gh) -> None:
    gh.job(1, "sast", conclusion="failure", attempt=1)
    gh.job(5, "sast", conclusion="success", attempt=2)
    gh.artifact(10, "scan-report", {"semgrep.json": SEMGREP})
    report = verify(conn, gh, policy("sast"))
    assert report.decision is Decision.VERIFIED
    assert report.requirements[0].job_id == 5


def test_duplicate_artifact_names_use_the_newest(conn, gh) -> None:
    """After a re-run, the same artifact name can appear twice; the newest wins."""
    gh.job(5, "sast")
    gh.artifact(10, "scan-report", {"semgrep.json": b'{"results": [ broken'})
    gh.artifact(11, "scan-report", {"semgrep.json": SEMGREP})
    assert verify(conn, gh, policy("sast")).decision is Decision.VERIFIED


def test_gate_inside_a_running_workflow(conn, gh) -> None:
    gh.run_conclusion = None
    gh.job(1, "sast", status="in_progress", conclusion=None)
    report = verify(conn, gh, policy("sast"))
    assert report.decision is Decision.INDETERMINATE
    assert failing(report)["job_success"] == "JOB_NOT_FINISHED"


def test_report_nested_in_artifact_folder_and_tampered_twin(conn, gh) -> None:
    gh.job(1, "sast")
    gh.artifact(10, "scan-report", {"reports/semgrep.json": SEMGREP})
    assert verify(conn, gh, policy("sast", report="reports/semgrep.json")).decision is (
        Decision.VERIFIED
    )
    gh.artifacts[0]["digest"] = "sha256:" + "0" * 64
    report = verify(conn, gh, policy("sast", report="reports/semgrep.json"))
    assert report.decision is Decision.BLOCKED
    assert "digest mismatch" in str(report.requirements[0].checks)


def test_masked_step_message_says_what_github_reported(conn, gh) -> None:
    """The job succeeded on GitHub; the message must not claim it 'ended failed'."""
    gh.job(1, "sast", notes=[[EXIT1]])
    gh.artifact(10, "scan-report", {"semgrep.json": SEMGREP})
    report = verify(conn, gh, policy("sast"))
    (check,) = [c for c in report.requirements[0].checks if c.check == "job_success"]
    assert "ended 'failed'" not in check.message
    assert check.message == (
        "Job 1 succeeded, but a step failed under continue-on-error "
        "(Process completed with exit code 1)"
    )
    assert not any("ended 'failed'" in w for w in report.warnings)
