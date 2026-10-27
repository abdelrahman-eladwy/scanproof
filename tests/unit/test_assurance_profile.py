"""Regression tests for the opt-in scanner-reported scope assurance profile.

This does not claim cryptographic scan completion. It rejects missing or empty
scanner claims under a release-grade policy without silently breaking v1alpha1
policies that only ask for a parseable report.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.engine import Decision, Outcome, RequirementInput, evaluate
from scanproof.policy.models import Policy
from scanproof.scanners.semgrep import SemgrepAdapter
from scanproof.scanners.trivy import TrivyAdapter

SHA = "a" * 40
PIPELINE = Pipeline(id=1, sha=SHA, status="success", ref="main")


def policy(*, strict: bool = True, tool: str = "semgrep", **extra) -> Policy:
    body = {
        "apiVersion": "scanproof.dev/v1alpha1",
        "kind": "PipelineAssurancePolicy",
        "project": {"provider": "gitlab", "id": "123"},
        "requirements": [
            {"id": "SCAN", "tool": tool, "job_name": "scanner", "report_path": "report.json"}
        ],
    }
    if strict:
        body["assurance"] = {"minimum_level": "reported_scope"}
    body.update(extra)
    return Policy.model_validate(body)


def result(ev, *, strict: bool = True, tool: str = "semgrep"):
    job = Job(
        id=99, name="scanner", status=JobStatus.SUCCESS,
        commit_sha=SHA,
    )
    inspected = InspectedJob(
        name="scanner", stage="security", latest=job,
        attempt_ids=[99], commit_matches_pipeline=True,
    )
    return evaluate(
        policy(strict=strict, tool=tool),
        PIPELINE,
        {"SCAN": RequirementInput(job=inspected, evidence=ev)},
    )


def scope_check(out):
    return next(check for check in out.requirements[0].checks if check.check == "reported_scope")


def test_legacy_report_only_policy_still_accepts_report_without_scope() -> None:
    ev = SemgrepAdapter().parse(b'{"results":[],"errors":[]}')
    assert result(ev, strict=False).decision is Decision.VERIFIED


def test_semgrep_scope_free_json_is_not_verified() -> None:
    ev = SemgrepAdapter().parse(b'{"results":[],"errors":[]}')
    out = result(ev)
    assert out.decision is Decision.INDETERMINATE
    assert (scope_check(out).outcome, scope_check(out).code) == (
        Outcome.UNKNOWN, "SCAN_SCOPE_UNKNOWN",
    )


def test_semgrep_empty_scanned_paths_are_not_verified() -> None:
    ev = SemgrepAdapter().parse(b'{"results":[],"errors":[],"paths":{"scanned":[]}}')
    out = result(ev)
    assert out.decision is Decision.INDETERMINATE
    assert scope_check(out).code == "SCAN_SCOPE_CONFLICT"


def test_semgrep_scanned_file_with_zero_findings_passes() -> None:
    ev = SemgrepAdapter().parse(
        b'{"results":[],"errors":[],"paths":{"scanned":["src/main.py"]}}'
    )
    out = result(ev)
    assert out.decision is Decision.VERIFIED
    assert scope_check(out).code == "REPORTED_SCOPE_PRESENT"


def test_trivy_missing_results_section_is_not_verified() -> None:
    ev = TrivyAdapter().parse(b'{"SchemaVersion":2,"ArtifactName":"example"}')
    out = result(ev, tool="trivy")
    assert out.decision is Decision.BLOCKED
    assert (scope_check(out).outcome, scope_check(out).code) == (
        Outcome.FAIL, "SCAN_RESULTS_MISSING",
    )


def test_trivy_empty_results_are_not_verified() -> None:
    ev = TrivyAdapter().parse(
        b'{"SchemaVersion":2,"ArtifactName":"example","Results":[]}'
    )
    out = result(ev, tool="trivy")
    assert out.decision is Decision.INDETERMINATE
    assert scope_check(out).code == "SCAN_SCOPE_EMPTY"


def test_trivy_result_without_a_target_is_not_verified() -> None:
    ev = TrivyAdapter().parse(
        b'{"SchemaVersion":2,"ArtifactName":"example","Results":[{}]}'
    )
    out = result(ev, tool="trivy")
    assert out.decision is Decision.BLOCKED
    assert scope_check(out).code == "SCAN_SCOPE_INVALID"


def test_trivy_reported_target_with_zero_findings_passes() -> None:
    ev = TrivyAdapter().parse(
        b'{"SchemaVersion":2,"ArtifactName":"example","Results":[{"Target":"app.jar","Vulnerabilities":[]}]}'
    )
    out = result(ev, tool="trivy")
    assert out.decision is Decision.VERIFIED
    assert scope_check(out).code == "REPORTED_SCOPE_PRESENT"


@pytest.mark.parametrize(
    "override",
    [
        {"enforcement": {"on_unknown": "warn"}},
        {"enforcement": {"on_nothing_applicable": "allow"}},
        {"requirements": [
            {"id":"SCAN","tool":"semgrep","job_name":"scanner","report_path":"report.json",
             "checks":{"report_required":False}}
        ]},
    ],
)
def test_strict_assurance_refuses_fail_open_configuration(override) -> None:
    with pytest.raises(ValidationError, match="reported_scope assurance requires"):
        policy(**override)


def test_invalid_profile_name_rejected() -> None:
    with pytest.raises(ValidationError, match="minimum_level"):
        policy(assurance={"minimum_level": "cryptographically_secure"})


def test_parallel_instances_respect_required_scope() -> None:
    good = SemgrepAdapter().parse(
        b'{"results":[],"errors":[],"paths":{"scanned":["src/main.py"]}}'
    )
    unknown = SemgrepAdapter().parse(b'{"results":[],"errors":[]}')
    job = Job(id=99, name="scanner", status=JobStatus.SUCCESS, commit_sha=SHA)
    inspected = InspectedJob(
        name="scanner", stage="security", latest=job,
        attempt_ids=[99], commit_matches_pipeline=True,
    )
    out = evaluate(
        policy(),
        PIPELINE,
        {"SCAN": RequirementInput(instances=[
            ("part1", RequirementInput(job=inspected, evidence=good)),
            ("part2", RequirementInput(job=inspected, evidence=unknown)),
        ])},
    )
    assert out.decision is Decision.INDETERMINATE
    assert any(c.check == "reported_scope [part2]" and c.outcome is Outcome.UNKNOWN
               for c in out.requirements[0].checks)
