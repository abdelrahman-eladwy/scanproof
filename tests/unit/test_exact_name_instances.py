"""#59: a job named exactly like the requirement must not hide its instances.

Before the fix, `find_jobs` returned early on an exact name match. A passing `sast` job then
stood in for failing `sast (py)`, `sast: [py]`, `sast 1/2`, `trigger > sast` or
`caller / sast` jobs, a false VERIFIED. Now the exact job is one more instance, and every
instance must pass ("evaluate all").

Compatibility: pipelines with only an exact job, or only instances, keep their outcomes. A
pipeline with both now needs every one of them to pass. ScanProof cannot tell a deliberate,
unrelated `sast 1/2` from a leg of `sast`; rename one if they really are unrelated.
"""

from __future__ import annotations

import pytest

from scanproof.connectors.github import GitHubConnector
from scanproof.policy.engine import Decision, Outcome
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.conftest import BASE, FIXTURES
from tests.fake_github import API, EXIT1, REPO, RUN, FakeGitHub
from tests.fake_gitlab import FakeGitLab

SEMGREP = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()
REPORT = {"semgrep.json": SEMGREP}


def failing(report) -> dict[str, str]:
    return {c.check: c.code for c in report.requirements[0].checks if c.outcome is not Outcome.PASS}


# ---------------------------------------------------------------- GitLab


def gitlab_policy(job: str = "semgrep-sast") -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": "123"},
            "requirements": [
                {
                    "id": "SAST",
                    "tool": "semgrep",
                    "job_name": job,
                    "report_path": "semgrep.json",
                    "checks": {"scanner_errors_allowed": 0, "minimum_scanned_files": 1},
                }
            ],
        }
    )


@pytest.fixture
def gl(mock_api) -> FakeGitLab:
    return FakeGitLab(mock_api)


def gitlab_verify(connector, gl: FakeGitLab, job: str = "semgrep-sast"):
    gl.install()
    return verify_pipeline(
        connector, gitlab_policy(job), instance_url=BASE, project="123", pipeline_id=1042
    )


@pytest.mark.parametrize(
    "instance",
    ["semgrep-sast: [py]", "semgrep-sast (py)"],
    ids=["gitlab-matrix", "matrix-paren"],
)
def test_gitlab_exact_job_does_not_hide_failing_matrix_instance(connector, gl, instance) -> None:
    gl.job(1, "semgrep-sast", files=REPORT)
    gl.job(2, instance, status="failed", files=REPORT)
    report = gitlab_verify(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {f"job_success [{instance}]": "JOB_NOT_SUCCESS"}
    assert sorted(report.requirements[0].instances) == sorted(["semgrep-sast", instance])


def test_gitlab_exact_job_does_not_hide_failing_parallel_instance(connector, gl) -> None:
    gl.job(1, "semgrep-sast", files=REPORT)
    gl.job(2, "semgrep-sast 1/2", status="failed", files=REPORT)
    gl.job(3, "semgrep-sast 2/2", files=REPORT)
    report = gitlab_verify(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {"job_success [semgrep-sast 1/2]": "JOB_NOT_SUCCESS"}


def test_gitlab_exact_job_does_not_hide_missing_parallel_index(connector, gl) -> None:
    """The parallel total still reports absent indices when an exact job is present."""
    gl.job(1, "semgrep-sast", files=REPORT)
    gl.job(2, "semgrep-sast 1/2", files=REPORT)
    report = gitlab_verify(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {"job_present [semgrep-sast 2/2]": "REQUIRED_JOB_ABSENT"}


def test_gitlab_exact_job_does_not_hide_failing_downstream_job(connector, gl) -> None:
    gl.job(1, "semgrep-sast", files=REPORT)
    gl.child("trigger", pipeline_id=2000).job(3000, "semgrep-sast", status="failed", files=REPORT)
    report = gitlab_verify(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {"job_success [trigger > semgrep-sast]": "JOB_NOT_SUCCESS"}


def test_gitlab_exact_job_does_not_hide_instance_without_report(connector, gl) -> None:
    gl.job(1, "semgrep-sast", files=REPORT)
    gl.job(2, "semgrep-sast: [go]", files={})
    report = gitlab_verify(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {"report [semgrep-sast: [go]]": "REPORT_MISSING"}


def test_gitlab_exact_job_and_passing_instances_verify(connector, gl) -> None:
    """Evaluate all, not 'ambiguous is unknown': a pipeline where everything passes ships."""
    gl.job(1, "semgrep-sast", files=REPORT)
    gl.job(2, "semgrep-sast: [py]", files=REPORT)
    gl.child("trigger", pipeline_id=2000).job(3000, "semgrep-sast", files=REPORT)
    report = gitlab_verify(connector, gl)
    assert report.decision is Decision.VERIFIED
    assert sorted(report.requirements[0].instances) == [
        "semgrep-sast",
        "semgrep-sast: [py]",
        "trigger > semgrep-sast",
    ]


def test_gitlab_exact_only_is_unchanged(connector, gl) -> None:
    gl.job(1, "semgrep-sast", files=REPORT)
    gl.job(2, "semgrep-sast-extra", status="failed")  # different name, not an instance
    report = gitlab_verify(connector, gl)
    assert report.decision is Decision.VERIFIED
    assert report.requirements[0].instances is None  # still a single-job requirement


def test_gitlab_failing_exact_job_still_blocks_with_passing_instances(connector, gl) -> None:
    gl.job(1, "semgrep-sast", status="failed", files=REPORT)
    gl.job(2, "semgrep-sast: [py]", files=REPORT)
    report = gitlab_verify(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {"job_success [semgrep-sast]": "JOB_NOT_SUCCESS"}


@pytest.mark.parametrize(
    ("status", "decision"), [("success", Decision.VERIFIED), ("failed", Decision.BLOCKED)]
)
def test_gitlab_instances_only_is_unchanged(connector, gl, status, decision) -> None:
    gl.job(1, "semgrep-sast: [py]", files=REPORT)
    gl.job(2, "semgrep-sast: [go]", status=status, files=REPORT)
    assert gitlab_verify(connector, gl).decision is decision


def test_qualified_name_still_matches_only_itself(connector, gl) -> None:
    """A downstream-qualified job_name is not widened by the fix."""
    gl.job(1, "semgrep-sast", status="failed", files=REPORT)  # not covered by the qualified name
    gl.child("trigger", pipeline_id=2000).job(3000, "semgrep-sast", files=REPORT)
    report = gitlab_verify(connector, gl, job="trigger > semgrep-sast")
    assert report.decision is Decision.VERIFIED
    assert report.requirements[0].instances is None


# ---------------------------------------------------------------- GitHub


@pytest.fixture
def gh(mock_api) -> FakeGitHub:
    return FakeGitHub(mock_api)


@pytest.fixture
def conn(sleeps):
    with GitHubConnector(API, "ghp_test", sleep=sleeps.append, max_retries=1) as c:
        yield c


def github_verify(conn, gh: FakeGitHub):
    pol = Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "github", "id": REPO},
            "requirements": [
                {
                    "id": "SAST",
                    "tool": "semgrep",
                    "job_name": "sast",
                    "artifact_name": "scan-report",
                    "report_path": "semgrep.json",
                }
            ],
        }
    )
    gh.artifact(10, "scan-report", REPORT)
    gh.install()
    return verify_pipeline(conn, pol, instance_url=API, project=REPO, pipeline_id=RUN)


@pytest.mark.parametrize(
    "instance", ["sast (py)", "security / sast"], ids=["github-matrix", "reusable-workflow"]
)
def test_github_exact_job_does_not_hide_failing_instance(conn, gh, instance) -> None:
    gh.job(1, "sast")
    gh.job(2, instance, conclusion="failure")
    report = github_verify(conn, gh)
    assert report.decision is Decision.BLOCKED
    # The fake run concludes 'success', so the connector reads the failed job as tolerated by
    # job-level continue-on-error: still a failure, with the masking named.
    assert failing(report) == {f"job_success [{instance}]": "FAILURE_MASKED_BY_ALLOW_FAILURE"}


def test_github_exact_job_does_not_hide_masked_matrix_instance(conn, gh) -> None:
    """continue-on-error on a leg: the leg reports success, the annotation shows the failure."""
    gh.job(1, "sast")
    gh.job(2, "sast (go)", notes=[[EXIT1]])
    report = github_verify(conn, gh)
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {"job_success [sast (go)]": "FAILURE_MASKED_BY_ALLOW_FAILURE"}


def test_github_exact_job_and_passing_instances_verify(conn, gh) -> None:
    gh.job(1, "sast")
    gh.job(2, "sast (py)")
    gh.job(3, "security / sast")
    report = github_verify(conn, gh)
    assert report.decision is Decision.VERIFIED
    assert sorted(report.requirements[0].instances) == ["sast", "sast (py)", "security / sast"]


def test_github_exact_only_is_unchanged(conn, gh) -> None:
    gh.job(1, "sast")
    report = github_verify(conn, gh)
    assert report.decision is Decision.VERIFIED
    assert report.requirements[0].instances is None


@pytest.mark.parametrize(
    ("conclusion", "decision"), [("success", Decision.VERIFIED), ("failure", Decision.BLOCKED)]
)
def test_github_instances_only_is_unchanged(conn, gh, conclusion, decision) -> None:
    gh.job(1, "sast (py)")
    gh.job(2, "sast (go)", conclusion=conclusion)
    assert github_verify(conn, gh).decision is decision
