"""End-to-end adversarial decision differential for GitLab and GitHub.

An unmodified successful scan must be VERIFIED.  A single harmful or unknown
provider mutation must not inherit that approval. Uses the real verification
orchestrator and connectors, not an engine-only mock.
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
FOREIGN_SHA = "f" * 40

# Which observable decision and reason must replace VERIFIED when valid scan
# evidence is removed or modified? Exact code is meaningful for gate operators.
FAULTS = {
    "job_absent": (Decision.BLOCKED, {"REQUIRED_JOB_ABSENT"}),
    "job_skipped": (Decision.BLOCKED, {"JOB_NOT_SUCCESS"}),
    "masked_failure": (Decision.BLOCKED, {"FAILURE_MASKED_BY_ALLOW_FAILURE"}),
    "report_absent": (Decision.BLOCKED, {"REPORT_MISSING"}),
    "report_empty": (Decision.BLOCKED, {"REPORT_MISSING", "REPORT_UNPARSEABLE"}),
    "report_truncated": (Decision.BLOCKED, {"REPORT_UNPARSEABLE"}),
    "report_wrong_schema": (Decision.BLOCKED, {"REPORT_UNPARSEABLE"}),
    "scope_zero": (Decision.BLOCKED, {"SCOPE_TOO_SMALL"}),
    "scope_unreported": (Decision.INDETERMINATE, {"SCOPE_UNKNOWN"}),
    "commit_mismatch": (Decision.BLOCKED, {"COMMIT_MISMATCH"}),
    "job_running": (Decision.INDETERMINATE, {"JOB_NOT_FINISHED"}),
    "read_not_authorized": (
        Decision.INDETERMINATE,
        {"EVIDENCE_UNAVAILABLE", "STEP_MASKING_UNKNOWN"},
    ),
    "retry_latest_failed": (
        Decision.BLOCKED,
        {"JOB_NOT_SUCCESS", "FAILURE_MASKED_BY_ALLOW_FAILURE"},
    ),
}


def make_policy(provider: str) -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {
                "provider": provider,
                "id": "123" if provider == "gitlab" else REPO,
            },
            "assurance": {"profile": "production"},
            "requirements": [
                {
                    "id": "SAST",
                    "tool": "semgrep",
                    "job_name": "sast",
                    "report_path": "semgrep.json",
                    **({"artifact_name": "scan-report"} if provider == "github" else {}),
                    "checks": {"minimum_scanned_files": 1, "scanner_errors_allowed": 0},
                }
            ],
        }
    )


def exercise(provider: str, fault: str, *, mock_api, connector, sleeps):
    if provider == "gitlab":
        gl = FakeGitLab(mock_api)
        if fault != "job_absent":
            job = gl.job(101, "sast", files={"semgrep.json": SEMGREP})
            if fault == "job_skipped":
                job.status = "skipped"
            elif fault == "masked_failure":
                job.status, job.allow_failure = "failed", True
            elif fault == "report_absent":
                job.files = {}
            elif fault == "report_empty":
                job.files = {"semgrep.json": b""}
            elif fault == "report_truncated":
                job.files = {"semgrep.json": b'{"results": [broken'}
            elif fault == "report_wrong_schema":
                job.files = {"semgrep.json": b'{"SchemaVersion": 2, "Results": []}'}
            elif fault == "scope_zero":
                job.files = {
                    "semgrep.json": b'{"results": [], "errors": [], "paths": {"scanned": []}}'
                }
            elif fault == "scope_unreported":
                job.files = {"semgrep.json": b'{"results": [], "errors": []}'}
            elif fault == "commit_mismatch":
                job.sha = FOREIGN_SHA
            elif fault == "job_running":
                job.status = "running"
            elif fault == "read_not_authorized":
                job.files = {"semgrep.json": 403}
            elif fault == "retry_latest_failed":
                gl.job(102, "sast", status="failed", files={"semgrep.json": SEMGREP})
        gl.install()
        return verify_pipeline(
            connector, make_policy(provider), instance_url=BASE, project="123", pipeline_id=1042
        )

    gh = FakeGitHub(mock_api)
    if fault != "job_absent":
        gh.job(101, "sast")
        contents = SEMGREP
        if fault == "job_skipped":
            gh.jobs[0]["conclusion"] = "skipped"
        elif fault == "masked_failure":
            gh.annotations[101] = [[EXIT1]]
        elif fault == "report_empty":
            contents = b""
        elif fault == "report_truncated":
            contents = b'{"results": [broken'
        elif fault == "report_wrong_schema":
            contents = b'{"SchemaVersion": 2, "Results": []}'
        elif fault == "scope_zero":
            contents = b'{"results": [], "errors": [], "paths": {"scanned": []}}'
        elif fault == "scope_unreported":
            contents = b'{"results": [], "errors": []}'
        elif fault == "commit_mismatch":
            gh.jobs[0]["head_sha"] = FOREIGN_SHA
        elif fault == "job_running":
            gh.jobs[0]["status"] = "in_progress"
            gh.jobs[0]["conclusion"] = None
        elif fault == "read_not_authorized":
            gh.annotations[101] = [403]
        elif fault == "retry_latest_failed":
            gh.run_attempt = 2
            gh.job(102, "sast", attempt=2, conclusion="failure")
        if fault != "report_absent":
            gh.artifact(200, "scan-report", {"semgrep.json": contents})
    gh.install()
    with GitHubConnector(API, "ghp_test", sleep=sleeps.append, max_retries=1) as conn:
        return verify_pipeline(
            conn, make_policy(provider), instance_url=API, project=REPO, pipeline_id=RUN
        )


@pytest.mark.parametrize("provider", ["gitlab", "github"])
def test_unmodified_baseline_is_verified(provider, mock_api, connector, sleeps):
    result = exercise(provider, "baseline", mock_api=mock_api, connector=connector, sleeps=sleeps)
    assert result.decision is Decision.VERIFIED
    assert result.exit_code == 0
    assert result.requirements[0].outcome is Outcome.PASS


@pytest.mark.parametrize("provider", ["gitlab", "github"])
@pytest.mark.parametrize("fault", list(FAULTS))
def test_one_adversarial_mutation_never_silently_passes(
    provider, fault, mock_api, connector, sleeps
):
    result = exercise(provider, fault, mock_api=mock_api, connector=connector, sleeps=sleeps)
    expected_decision, expected_codes = FAULTS[fault]
    assert result.decision is expected_decision, (provider, fault, result.requirements)
    assert result.exit_code == expected_decision.exit_code
    actual_codes = {
        check.code
        for check in result.requirements[0].checks
        if check.outcome in (Outcome.FAIL, Outcome.UNKNOWN)
    }
    assert actual_codes & expected_codes, (provider, fault, actual_codes)


def test_baseline_is_not_restored_by_failing_and_unknown_separate_requirements(mock_api, connector):
    """Aggregation contract: one failed scan always beats an unavailable scan."""
    gl = FakeGitLab(mock_api)
    gl.job(101, "sast", status="failed", files={"semgrep.json": SEMGREP})
    gl.job(102, "dependency", files={"semgrep.json": 403})
    body = make_policy("gitlab").model_dump(mode="json", exclude_none=True)
    body["requirements"].append(
        {
            "id": "SCA",
            "tool": "semgrep",
            "job_name": "dependency",
            "report_path": "semgrep.json",
            "checks": {"minimum_scanned_files": 1},
        }
    )
    gl.install()
    result = verify_pipeline(
        connector,
        Policy.model_validate(body),
        instance_url=BASE,
        project="123",
        pipeline_id=1042,
    )
    assert result.decision is Decision.BLOCKED
    assert result.exit_code == 1
    assert {r.outcome for r in result.requirements} == {Outcome.FAIL, Outcome.UNKNOWN}
