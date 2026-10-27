"""Adversarial decision matrix: unknown evidence must never silently become VERIFIED."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.engine import Decision, RequirementInput, evaluate
from scanproof.policy.models import Policy
from scanproof.scanners import get_adapter
from tests.conftest import FIXTURES

NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)
SHA = "a" * 40
PIPELINE = Pipeline(id=44, sha=SHA, ref="main", status="success")
REQ = {
    "id": "SAST",
    "tool": "semgrep",
    "job_name": "sast",
    "report_path": "semgrep.json",
    "checks": {"scanner_errors_allowed": 0, "minimum_scanned_files": 1},
}


def policy(**enforcement):
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": "1"},
            "requirements": [REQ],
            "enforcement": enforcement,
        }
    )


def job(status=JobStatus.SUCCESS, sha=SHA):
    item = Job(id=9, name="sast", status=status, commit_sha=sha, finished_at=NOW)
    return InspectedJob(
        name="sast", stage=None, latest=item, attempt_ids=[9],
        commit_matches_pipeline=sha == SHA,
    )


def report(path="semgrep/semgrep-clean.json"):
    return get_adapter("semgrep").parse((FIXTURES / path).read_bytes())


@pytest.mark.parametrize(
    ("input_data", "decision"),
    [
        (RequirementInput(), Decision.BLOCKED),
        (RequirementInput(absence_unknown="downstream API returned 403"), Decision.INDETERMINATE),
        (RequirementInput(job=job(), evidence_error="API 403"), Decision.INDETERMINATE),
        (
            RequirementInput(job=job(), evidence=get_adapter("semgrep").parse(None)),
            Decision.BLOCKED,
        ),
        (
            RequirementInput(job=job(), evidence=get_adapter("semgrep").parse(b"{}")),
            Decision.BLOCKED,
        ),
        (RequirementInput(job=job(status=JobStatus.FAILED), evidence=report()), Decision.BLOCKED),
        (RequirementInput(job=job(sha="b" * 40), evidence=report()), Decision.BLOCKED),
        (RequirementInput(job=job(), evidence=report()), Decision.VERIFIED),
    ],
)
def test_fail_closed_security_decisions(input_data, decision):
    actual = evaluate(policy(), PIPELINE, {"SAST": input_data}, now=NOW)
    assert actual.decision is decision
    assert actual.decision.exit_code == {Decision.VERIFIED: 0, Decision.BLOCKED: 1,
                                         Decision.INDETERMINATE: 2}[decision]


def test_matrix_requires_every_instance_to_pass():
    ok = RequirementInput(job=job(), evidence=report())
    failed = RequirementInput(job=job(status=JobStatus.FAILED), evidence=report())
    unknown = RequirementInput(job=job(), evidence_error="timeout")
    for bad, expected in [(failed, Decision.BLOCKED), (unknown, Decision.INDETERMINATE)]:
        result = evaluate(
            policy(), PIPELINE,
            {"SAST": RequirementInput(instances=[("linux", ok), ("windows", bad)])},
            now=NOW,
        )
        assert result.decision is expected


def test_unknown_warn_is_explicit_opt_in_not_default():
    unknown = {"SAST": RequirementInput(job=job(), evidence_error="API 403")}
    assert evaluate(policy(), PIPELINE, unknown, now=NOW).decision is Decision.INDETERMINATE
    result = evaluate(policy(on_unknown="warn"), PIPELINE, unknown, now=NOW)
    assert result.decision is Decision.VERIFIED
    assert result.warnings
