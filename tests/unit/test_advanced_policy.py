"""Waivers, scan freshness, same_target_as and multi-pipeline releases."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.engine import Decision, Outcome, RequirementInput, evaluate
from scanproof.policy.models import Policy
from scanproof.scanners import get_adapter
from tests.conftest import FIXTURES

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
SHA = "a" * 40
PIPE = Pipeline(id=1, sha=SHA, ref="main", status="success")


def job(name="sast", finished=NOW - timedelta(hours=1), status=JobStatus.SUCCESS) -> InspectedJob:
    j = Job(id=1, name=name, status=status, commit_sha=SHA, finished_at=finished)
    return InspectedJob(
        name=name, stage=None, latest=j, attempt_ids=[1], commit_matches_pipeline=True
    )


def evidence(tool: str, path: str):
    return get_adapter(tool).parse((FIXTURES / path).read_bytes())


def policy(requirements: list[dict], waivers: list[dict] | None = None, **enforcement) -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": "1"},
            "requirements": requirements,
            "waivers": waivers or [],
            "enforcement": enforcement,
        }
    )


SEMGREP_ERRORS = {
    "id": "SAST",
    "tool": "semgrep",
    "job_name": "sast",
    "report_path": "r.json",
    "checks": {"scanner_errors_allowed": 0},
}


def waiver(**over) -> dict:
    base = {
        "requirement": "SAST",
        "check": "scanner_errors",
        "reason": "Parser bug on vendored code, tracked in SEC-123",
        "approved_by": "security-team",
        "expires": "2026-11-30",
    }
    return base | over


def run(pol: Policy, inputs: dict, now: datetime = NOW):
    return evaluate(pol, PIPE, inputs, now=now)


def semgrep_errors_input() -> dict:
    return {
        "SAST": RequirementInput(
            job=job(), evidence=evidence("semgrep", "semgrep/semgrep-errors.json")
        )
    }


# ---------------------------------------------------------------- waivers


def test_without_a_waiver_scanner_errors_block() -> None:
    assert run(policy([SEMGREP_ERRORS]), semgrep_errors_input()).decision is Decision.BLOCKED


def test_active_waiver_turns_the_failure_into_waived() -> None:
    result = run(policy([SEMGREP_ERRORS], [waiver()]), semgrep_errors_input())
    assert result.decision is Decision.VERIFIED
    (check,) = [c for c in result.requirements[0].checks if c.check == "scanner_errors"]
    assert check.outcome is Outcome.WAIVED
    assert "SEC-123" in check.message and "security-team" in check.message
    assert any("applied" in w for w in result.warnings)


def test_expired_waiver_does_nothing_and_says_so() -> None:
    result = run(policy([SEMGREP_ERRORS], [waiver(expires="2026-10-26")]), semgrep_errors_input())
    assert result.decision is Decision.BLOCKED
    assert any("expired on 2026-10-26" in w for w in result.warnings)


def test_waiver_on_its_last_day_still_applies() -> None:
    result = run(policy([SEMGREP_ERRORS], [waiver(expires="2026-10-27")]), semgrep_errors_input())
    assert result.decision is Decision.VERIFIED


def test_future_waiver_is_not_applied_yet() -> None:
    w = waiver(created="2026-11-01", expires="2026-11-30")
    result = run(policy([SEMGREP_ERRORS], [w]), semgrep_errors_input())
    assert result.decision is Decision.BLOCKED
    assert any("starts on 2026-11-01" in w for w in result.warnings)


def test_waiver_for_another_code_matches_nothing() -> None:
    result = run(policy([SEMGREP_ERRORS], [waiver(code="SOMETHING_ELSE")]), semgrep_errors_input())
    assert result.decision is Decision.BLOCKED
    assert any("matched nothing" in w for w in result.warnings)


def test_waiver_covers_every_instance_of_a_check() -> None:
    req = {**SEMGREP_ERRORS, "checks": {"job_success": True, "report_required": False}}
    failed = RequirementInput(job=job(status=JobStatus.FAILED))
    ok = RequirementInput(job=job())
    inputs = {"SAST": RequirementInput(instances=[("sast 1/2", ok), ("sast 2/2", failed)])}
    result = run(policy([req], [waiver(check="job_success")]), inputs)
    assert result.decision is Decision.VERIFIED
    codes = {c.check: c.outcome for c in result.requirements[0].checks}
    assert codes["job_success [sast 2/2]"] is Outcome.WAIVED


def test_waiver_can_cover_unknown_too() -> None:
    req = {**SEMGREP_ERRORS, "checks": {"minimum_endpoints": 1}}
    inputs = {
        "SAST": RequirementInput(
            job=job(), evidence=evidence("semgrep", "semgrep/semgrep-clean.json")
        )
    }
    blocked = run(policy([req]), inputs)
    assert blocked.decision is Decision.INDETERMINATE
    waived = run(policy([req], [waiver(check="minimum_endpoints")]), inputs)
    assert waived.decision is Decision.VERIFIED


@pytest.mark.parametrize(
    ("waivers", "enforcement", "message"),
    [
        ([waiver(requirement="NOPE")], {}, "unknown requirement"),
        ([waiver(reason="short")], {}, "at least 10"),
        ([waiver(expires="not a date")], {}, "date"),
        ([waiver()], {"max_waiver_days": 30}, "'created' is required"),
        ([waiver(created="2026-09-01")], {"max_waiver_days": 30}, "runs 90 days"),
        ([waiver(created="2026-12-01")], {}, "expires before it starts"),
        ([waiver(extra="x")], {}, "Extra inputs"),
    ],
)
def test_invalid_waivers(waivers, enforcement, message) -> None:
    with pytest.raises(ValueError, match=message):
        policy([SEMGREP_ERRORS], waivers, **enforcement)


def test_waiver_within_max_days_is_accepted() -> None:
    policy([SEMGREP_ERRORS], [waiver(created="2026-11-01")], max_waiver_days=30)


# ---------------------------------------------------------------- freshness


@pytest.mark.parametrize(
    ("finished", "outcome", "code"),
    [
        (NOW - timedelta(hours=2), Outcome.PASS, "SCAN_FRESH"),
        (NOW - timedelta(hours=30), Outcome.FAIL, "SCAN_TOO_OLD"),
        (None, Outcome.UNKNOWN, "SCAN_AGE_UNKNOWN"),
        ((NOW - timedelta(hours=30)).replace(tzinfo=None), Outcome.FAIL, "SCAN_TOO_OLD"),
    ],
)
def test_max_age_hours(finished, outcome, code) -> None:
    req = {**SEMGREP_ERRORS, "checks": {"max_age_hours": 24, "report_required": False}}
    result = run(policy([req]), {"SAST": RequirementInput(job=job(finished=finished))})
    (check,) = [c for c in result.requirements[0].checks if c.check == "max_age"]
    assert (check.outcome, check.code) == (outcome, code)


def test_jenkins_stages_get_finish_times(mock_api, sleeps) -> None:
    from scanproof.connectors.jenkins import JenkinsConnector
    from tests.unit.test_jenkins import BASE, serve

    serve(mock_api, "sast-ok")
    with JenkinsConnector(BASE, "t", username="u", sleep=sleeps.append) as c:
        (j,) = c.list_jobs("sast-ok", 1)
    import json

    node = json.loads((FIXTURES / "jenkins-real/sast-ok/stages_tree.json").read_text())
    node = node["data"]["stages"][0]
    end = (node["startTimeMillis"] + node["totalDurationMillis"]) / 1000
    assert j.finished_at == datetime.fromtimestamp(end, UTC)


# ---------------------------------------------------------------- same_target_as


def two(sbom: tuple[str, str], scan: tuple[str, str]):
    reqs = [
        {"id": "CONTAINER", "tool": scan[0], "job_name": "scan", "report_path": "s.json"},
        {
            "id": "SBOM",
            "tool": sbom[0],
            "job_name": "sbom",
            "report_path": "b.json",
            "checks": {"same_target_as": "CONTAINER"},
        },
    ]
    inputs = {
        "CONTAINER": RequirementInput(job=job("scan"), evidence=evidence(*scan)),
        "SBOM": RequirementInput(job=job("sbom"), evidence=evidence(*sbom)),
    }
    result = run(policy(reqs), inputs)
    (check,) = [c for c in result.requirements[1].checks if c.check == "same_target"]
    return check


def test_sbom_and_container_scan_of_one_image() -> None:
    check = two(
        ("cyclonedx", "cyclonedx/trivy-image.cdx.json"), ("trivy", "trivy/trivy-python.json")
    )
    assert check.code == "SAME_TARGET"


def test_two_scanners_on_one_image() -> None:
    check = two(("grype", "grype/grype-alpine.json"), ("trivy", "trivy/trivy-alpine.json"))
    assert check.code == "SAME_TARGET"


def test_same_tag_different_day_is_a_different_image() -> None:
    """Real: python:3.12-slim moved between the Trivy (Oct 26) and Grype (Oct 27) scans."""
    check = two(("grype", "grype/grype-python-trimmed.json"), ("trivy", "trivy/trivy-python.json"))
    assert (check.code, check.outcome) == ("TARGET_DIFFERS", Outcome.FAIL)


def test_sbom_without_a_digest_is_unknown() -> None:
    check = two(
        ("cyclonedx", "cyclonedx/syft-alpine.cdx.json"), ("trivy", "trivy/trivy-alpine.json")
    )
    assert (check.code, check.outcome) == ("TARGET_UNKNOWN", Outcome.UNKNOWN)


@pytest.mark.parametrize("target", ["SBOM", "NOPE"])
def test_same_target_as_must_name_another_requirement(target) -> None:
    with pytest.raises(ValueError, match="same_target_as"):
        policy([{**SEMGREP_ERRORS, "id": "SBOM", "checks": {"same_target_as": target}}])


def test_waiver_covers_only_its_own_check() -> None:
    """A waiver for scanner_errors must not hide a failed job (over-broad waiver)."""
    inputs = {
        "SAST": RequirementInput(
            job=job(status=JobStatus.FAILED),
            evidence=evidence("semgrep", "semgrep/semgrep-errors.json"),
        )
    }
    result = run(policy([SEMGREP_ERRORS], [waiver()]), inputs)
    assert result.decision is Decision.BLOCKED
    outcomes = {c.check: c.outcome for c in result.requirements[0].checks}
    assert outcomes["scanner_errors"] is Outcome.WAIVED
    assert outcomes["job_success"] is Outcome.FAIL


def test_waiver_never_touches_a_passing_check() -> None:
    inputs = {
        "SAST": RequirementInput(
            job=job(), evidence=evidence("semgrep", "semgrep/semgrep-clean.json")
        )
    }
    result = run(policy([SEMGREP_ERRORS], [waiver()]), inputs)
    outcomes = {c.check: c.outcome for c in result.requirements[0].checks}
    assert outcomes["scanner_errors"] is Outcome.PASS
    assert any("matched nothing" in w for w in result.warnings)


def test_waiver_cannot_turn_not_applicable_into_a_pass() -> None:
    """Otherwise 'nothing applied' (INDETERMINATE) could be waived into VERIFIED."""
    req = {**SEMGREP_ERRORS, "applies_to": {"refs": ["release/*"]}}
    w = waiver(check="applies_to")
    result = run(policy([req], [w]), semgrep_errors_input())
    assert result.requirements[0].outcome is Outcome.NOT_APPLICABLE
    assert result.decision is Decision.INDETERMINATE
