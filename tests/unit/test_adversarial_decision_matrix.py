"""Adversarial decision matrix: unknown evidence must never silently become VERIFIED."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from scanproof.evidence.collector import find_jobs, match_jobs
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


def policy(*, instances=None, profile="compatible", **enforcement):
    req = REQ if instances is None else {**REQ, "instances": instances}
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": "1"},
            "assurance": {"profile": profile},
            "requirements": [req],
            "enforcement": enforcement,
        }
    )


def job(status=JobStatus.SUCCESS, sha=SHA):
    item = Job(id=9, name="sast", status=status, commit_sha=sha, finished_at=NOW)
    return InspectedJob(
        name="sast",
        stage=None,
        latest=item,
        attempt_ids=[9],
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
    assert (
        actual.decision.exit_code
        == {Decision.VERIFIED: 0, Decision.BLOCKED: 1, Decision.INDETERMINATE: 2}[decision]
    )


def test_matrix_requires_every_instance_to_pass():
    ok = RequirementInput(job=job(), evidence=report())
    failed = RequirementInput(job=job(status=JobStatus.FAILED), evidence=report())
    unknown = RequirementInput(job=job(), evidence_error="timeout")
    for bad, expected in [(failed, Decision.BLOCKED), (unknown, Decision.INDETERMINATE)]:
        result = evaluate(
            policy(),
            PIPELINE,
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


def named(name: str, status=JobStatus.SUCCESS) -> InspectedJob:
    item = Job(id=hash(name) % 10_000, name=name, status=status, commit_sha=SHA, finished_at=NOW)
    return InspectedJob(
        name=name, stage=None, latest=item, attempt_ids=[item.id], commit_matches_pipeline=True
    )


@pytest.mark.parametrize(
    "instance", ["sast (py)", "sast: [py]", "sast 1/1", "trigger > sast", "caller / sast"]
)
def test_exact_name_job_cannot_hide_a_failing_instance(instance):
    """#59: a passing job named exactly 'sast' must not stand in for a failing instance."""
    jobs = [named("sast"), named(instance, JobStatus.FAILED)]
    matches, missing = find_jobs(jobs, "sast")  # what verification.py feeds the engine
    assert sorted(j.name for j in matches) == sorted(["sast", instance])
    assert missing == []
    inputs = {
        "SAST": RequirementInput(
            instances=[(j.name, RequirementInput(job=j, evidence=report())) for j in matches]
        )
    }
    assert evaluate(policy(), PIPELINE, inputs, now=NOW).decision is Decision.BLOCKED


def matrix_inputs(pol: Policy, jobs: list[InspectedJob]) -> dict[str, RequirementInput]:
    """What verification.py feeds the engine for a matrix requirement."""
    req = pol.requirements[0]
    m = match_jobs(jobs, req.job_name, req.instances)
    present = [(j.name, RequirementInput(job=j, evidence=report())) for j in m.jobs]
    absent = [(n, RequirementInput(declared_instance=lab)) for n, lab in m.missing_declared]
    absent += [(n, RequirementInput()) for n in m.missing]
    return {
        "SAST": RequirementInput(
            instances=present + absent, undeclared_instances=m.undeclared_legs or None
        )
    }


@pytest.mark.parametrize("style", ["sast: [{}]", "sast ({})"], ids=["gitlab", "github"])
@pytest.mark.parametrize(
    ("instances", "profile", "decision"),
    [
        (["py", "js"], "compatible", Decision.BLOCKED),
        (["py", "js"], "production", Decision.BLOCKED),
        (None, "production", Decision.INDETERMINATE),
        # The documented compatible gap (#60): without a declaration a removed leg is unseen.
        (None, "compatible", Decision.VERIFIED),
    ],
)
def test_removed_matrix_leg(style, instances, profile, decision):
    """#60: `js` was removed from the matrix; only the passing `py` leg ran."""
    pol = policy(instances=instances, profile=profile)
    result = evaluate(pol, PIPELINE, matrix_inputs(pol, [named(style.format("py"))]), now=NOW)
    assert result.decision is decision
    if decision is Decision.VERIFIED:
        assert any("declares no `instances`" in w for w in result.warnings)


def copy_inputs(pol: Policy, jobs: list[InspectedJob]) -> dict[str, RequirementInput]:
    """What verification.py feeds the engine for a requirement with prefixed copies."""
    req = pol.requirements[0]
    m = match_jobs(jobs, req.job_name, req.instances, req.copies)
    present = [(j.name, RequirementInput(job=j, evidence=report())) for j in m.jobs]
    absent = [(n, RequirementInput(missing_copy=path)) for n, path in m.missing_copies]
    return {
        "SAST": RequirementInput(
            instances=present + absent, undeclared_copies=m.undeclared_copies or None
        )
    }


@pytest.mark.parametrize(
    ("kept", "copies"),
    [
        ("svc-a > sast", ["svc-a", "svc-b"]),  # GitLab downstream: svc-b's trigger removed
        ("api / sast", ["api", "web"]),  # GitHub reusable workflow: web caller removed
        (
            "Scan / Matrix - LANG = 'py' / sast",
            ["Scan / Matrix - LANG = 'py'", "Scan / Matrix - LANG = 'go'"],
        ),
    ],
    ids=["gitlab-downstream", "github-reusable", "jenkins-stage"],
)
@pytest.mark.parametrize(
    ("declared", "profile", "decision"),
    [
        (True, "compatible", Decision.BLOCKED),
        (True, "production", Decision.BLOCKED),
        (False, "production", Decision.INDETERMINATE),
        # The documented compatible gap (#65): without a declaration a removed copy is unseen.
        (False, "compatible", Decision.VERIFIED),
    ],
)
def test_removed_prefixed_copy(kept, copies, declared, profile, decision):
    """#65: one of two prefixed copies was removed; only the passing one ran."""
    body = policy(profile=profile).model_dump(mode="json", exclude_none=True)
    if declared:
        body["requirements"][0]["copies"] = copies
    pol = Policy.model_validate(body)
    result = evaluate(pol, PIPELINE, copy_inputs(pol, [named(kept)]), now=NOW)
    assert result.decision is decision
    if decision is Decision.VERIFIED:
        assert any("declares no `copies`" in w for w in result.warnings)
