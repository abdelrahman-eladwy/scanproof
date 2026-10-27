"""Acceptance suite from docs/milestones/M3-policy-engine.md, end to end through
verify_pipeline() with a fake GitLab and REAL Semgrep/Trivy reports."""

from __future__ import annotations

import json

import pytest

from scanproof.policy.engine import Decision, Outcome
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.conftest import BASE, FIXTURES
from tests.fake_gitlab import FakeGitLab

PYTHON_DIGEST = "sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"
SEMGREP_OK = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()
SEMGREP_ERRORS = (FIXTURES / "semgrep/semgrep-errors.json").read_bytes()
TRIVY_PYTHON = (FIXTURES / "trivy/trivy-python.json").read_bytes()
TRIVY_ALPINE = (FIXTURES / "trivy/trivy-alpine.json").read_bytes()


def make_policy(**overrides) -> Policy:
    data = {
        "apiVersion": "scanproof.dev/v1alpha1",
        "kind": "PipelineAssurancePolicy",
        "metadata": {"name": "test"},
        "project": {"provider": "gitlab", "id": "123"},
        "requirements": [
            {
                "id": "SAST-001",
                "tool": "semgrep",
                "job_name": "semgrep-sast",
                "report_path": "semgrep.json",
                "checks": {
                    "scanner_errors_allowed": 0,
                    "minimum_scanned_files": 1,
                    "required_paths": ["examples/gitlab-ci/sample-app/"],
                },
            },
            {
                "id": "CONTAINER-001",
                "tool": "trivy",
                "job_name": "trivy-image",
                "report_path": "trivy.json",
                "checks": {"image_digest_must_match": PYTHON_DIGEST},
            },
        ],
        **overrides,
    }
    return Policy.model_validate(data)


@pytest.fixture
def gl(mock_api) -> FakeGitLab:
    return FakeGitLab(mock_api)


def happy(gl: FakeGitLab) -> FakeGitLab:
    gl.job(8821, "semgrep-sast", files={"semgrep.json": SEMGREP_OK})
    gl.job(8830, "trivy-image", files={"trivy.json": TRIVY_PYTHON})
    return gl


def run(connector, gl: FakeGitLab, policy: Policy | None = None):
    gl.install()
    return verify_pipeline(
        connector, policy or make_policy(), instance_url=BASE, project="123", pipeline_id=1042
    )


def req(report, rid):
    return next(r for r in report.requirements if r.id == rid)


def codes(report, rid):
    return {c.code for c in req(report, rid).checks if c.outcome in (Outcome.FAIL, Outcome.UNKNOWN)}


# ---------------------------------------------------------------- the table


def test_both_scans_valid_is_verified(connector, gl) -> None:
    report = run(connector, happy(gl))
    assert report.decision is Decision.VERIFIED
    assert report.exit_code == 0
    assert all(r.outcome is Outcome.PASS for r in report.requirements)


def test_findings_are_reported_not_judged(connector, gl) -> None:
    report = run(connector, happy(gl))
    assert report.decision is Decision.VERIFIED
    assert req(report, "SAST-001").findings == {"ERROR": 4, "WARNING": 2, "total": 6}
    assert req(report, "CONTAINER-001").findings["HIGH"] == 4


def test_sast_job_absent(connector, gl) -> None:
    gl.job(8830, "trivy-image", files={"trivy.json": TRIVY_PYTHON})
    report = run(connector, gl)
    assert report.decision is Decision.BLOCKED and report.exit_code == 1
    assert codes(report, "SAST-001") == {"REQUIRED_JOB_ABSENT"}
    assert req(report, "CONTAINER-001").outcome is Outcome.PASS


def test_failure_masked_by_allow_failure(connector, gl) -> None:
    happy(gl).jobs[0].status = "failed"
    gl.jobs[0].allow_failure = True
    report = run(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert "FAILURE_MASKED_BY_ALLOW_FAILURE" in codes(report, "SAST-001")


def test_job_succeeded_but_no_report(connector, gl) -> None:
    happy(gl).jobs[0].files = {}
    report = run(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert codes(report, "SAST-001") == {"REPORT_MISSING"}


def test_job_without_artifacts_archive(connector, gl) -> None:
    happy(gl).jobs[0].archive = False
    report = run(connector, gl)
    assert codes(report, "SAST-001") == {"REPORT_MISSING"}


def test_invalid_report(connector, gl) -> None:
    happy(gl).jobs[0].files = {"semgrep.json": b'{"results": [ truncated'}
    report = run(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert codes(report, "SAST-001") == {"REPORT_UNPARSEABLE"}


def test_scanner_errors(connector, gl) -> None:
    happy(gl).jobs[0].files = {"semgrep.json": SEMGREP_ERRORS}
    data = json.loads(make_policy().model_dump_json())
    data["requirements"][0]["checks"]["required_paths"] = None  # errors fixture scanned /tmp
    report = run(connector, gl, Policy.model_validate(data))
    assert report.decision is Decision.BLOCKED
    assert codes(report, "SAST-001") == {"SCANNER_ERRORS"}


def test_scanner_warnings_can_be_ignored(connector, gl) -> None:
    happy(gl).jobs[0].files = {"semgrep.json": SEMGREP_ERRORS}
    data = json.loads(make_policy().model_dump_json())
    data["requirements"][0]["checks"].update(ignore_scanner_warnings=True, required_paths=None)
    report = run(connector, gl, Policy.model_validate(data))
    assert req(report, "SAST-001").outcome is Outcome.PASS


def test_api_403_on_report_is_unknown_not_missing(connector, gl) -> None:
    happy(gl).jobs[0].files = {"semgrep.json": 403}
    report = run(connector, gl)
    assert report.decision is Decision.INDETERMINATE and report.exit_code == 2
    assert codes(report, "SAST-001") == {"EVIDENCE_UNAVAILABLE"}


def test_report_from_another_commit(connector, gl) -> None:
    happy(gl).jobs[0].sha = "ffffffffffffffffffffffffffffffffffffffff"
    report = run(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert codes(report, "SAST-001") == {"COMMIT_MISMATCH"}


def test_trivy_scanned_a_different_image(connector, gl) -> None:
    happy(gl).jobs[1].files = {"trivy.json": TRIVY_ALPINE}
    report = run(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert codes(report, "CONTAINER-001") == {"IMAGE_DIGEST_MISMATCH"}
    assert req(report, "SAST-001").outcome is Outcome.PASS


def test_retried_job_failed_then_succeeded(connector, gl) -> None:
    gl.job(8800, "semgrep-sast", status="failed", files={"semgrep.json": 404})
    happy(gl)
    report = run(connector, gl)
    assert report.decision is Decision.VERIFIED
    sast = req(report, "SAST-001")
    assert sast.job_id == 8821
    assert any("after 2 attempts" in c.message for c in sast.checks)
    assert any("retried" in w for w in report.warnings)


def test_retried_job_succeeded_then_failed_uses_latest(connector, gl) -> None:
    happy(gl)
    gl.job(8850, "semgrep-sast", status="failed", files={"semgrep.json": SEMGREP_OK})
    report = run(connector, gl)
    assert report.decision is Decision.BLOCKED
    assert "JOB_NOT_SUCCESS" in codes(report, "SAST-001")


# ---------------------------------------------------------------- beyond the table


def test_required_path_not_scanned(connector, gl) -> None:
    data = json.loads(make_policy().model_dump_json())
    data["requirements"][0]["checks"]["required_paths"] = ["src/"]
    report = run(connector, happy(gl), Policy.model_validate(data))
    assert codes(report, "SAST-001") == {"REQUIRED_PATH_NOT_SCANNED"}


def test_running_job_is_indeterminate(connector, gl) -> None:
    happy(gl).jobs[1].status = "running"
    report = run(connector, gl)
    assert report.decision is Decision.INDETERMINATE
    assert "JOB_NOT_FINISHED" in codes(report, "CONTAINER-001")


def test_on_unknown_warn(connector, gl) -> None:
    happy(gl).jobs[0].files = {"semgrep.json": 403}
    report = run(connector, gl, make_policy(enforcement={"on_unknown": "warn"}))
    assert report.decision is Decision.VERIFIED
    assert any("on_unknown=warn" in w for w in report.warnings)


def test_fail_beats_unknown(connector, gl) -> None:
    happy(gl).jobs[0].files = {"semgrep.json": 403}
    gl.jobs[1].files = {"trivy.json": TRIVY_ALPINE}
    assert run(connector, gl).decision is Decision.BLOCKED


def test_requirement_not_applicable_on_other_refs(connector, gl) -> None:
    gl.ref = "feature/x"
    gl.job(8821, "semgrep-sast", files={"semgrep.json": SEMGREP_OK})  # no trivy job at all
    data = json.loads(make_policy().model_dump_json())
    data["requirements"][1]["applies_to"] = {"refs": ["main", "release/*"]}
    report = run(connector, gl, Policy.model_validate(data))
    assert req(report, "CONTAINER-001").outcome is Outcome.NOT_APPLICABLE
    assert report.decision is Decision.VERIFIED


def test_shared_report_is_downloaded_once(connector, gl, mock_api) -> None:
    happy(gl)
    data = json.loads(make_policy().model_dump_json())
    data["requirements"].append({**data["requirements"][0], "id": "SAST-002"})
    report = run(connector, gl, Policy.model_validate(data))
    assert report.decision is Decision.VERIFIED
    downloads = [c for c in mock_api.calls if c.request.url.path.endswith("/semgrep.json")]
    assert len(downloads) == 1


def test_evidence_is_included_in_report(connector, gl) -> None:
    report = run(connector, happy(gl))
    assert report.evidence["CONTAINER-001"].target.artifact_name == "python:3.12-slim"
    assert report.evidence["SAST-001"].source.job_id == 8821
