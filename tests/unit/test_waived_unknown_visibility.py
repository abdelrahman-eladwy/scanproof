"""Regression tests for #132: waiving UNKNOWN must remain auditable."""

from datetime import date

import pytest

from scanproof.policy.engine import (
    CheckResult,
    Outcome,
    RequirementResult,
    _apply_waivers,
)
from scanproof.policy.models import Policy, Waiver


def _result(outcome: Outcome, *, check: str = "report") -> RequirementResult:
    return RequirementResult(
        id="sast", description=None, tool="sarif", job_name="scan", job_id=1,
        outcome=outcome,
        checks=[CheckResult(check=check, outcome=outcome, code="EVIDENCE_UNAVAILABLE",
                            message="Provider API could not be read")],
    )


def _policy(*, expires: str = "2026-12-01", created: str | None = None) -> Policy:
    waiver = {
        "requirement": "sast", "check": "report", "code": "EVIDENCE_UNAVAILABLE",
        "approved_by": "security-owner", "reason": "Tracked risk acceptance #132",
        "expires": expires,
    }
    if created is not None:
        waiver["created"] = created
    return Policy.model_construct(waivers=[Waiver.model_validate(waiver)])


def test_waived_unknown_has_explicit_report_provenance_and_warning():
    result = _result(Outcome.UNKNOWN)
    warnings = _apply_waivers(_policy(), [result], date(2026, 10, 31))
    assert result.outcome is Outcome.PASS  # combine treats all-WAIVED as accepted
    assert result.checks[0].outcome is Outcome.WAIVED
    assert result.checks[0].waived_unknown is True
    assert result.model_dump(mode="json")["checks"][0]["waived_unknown"] is True
    assert any("WAIVED_UNKNOWN:" in w and "sast/report" in w for w in warnings)
    assert any("was UNKNOWN, not verified" in w for w in warnings)


@pytest.mark.parametrize(
    ("expires", "created"),
    [("2026-10-30", None), ("2026-12-01", "2026-11-01")],
)
def test_inactive_waiver_does_not_mark_unknown(expires: str, created: str | None):
    result = _result(Outcome.UNKNOWN)
    warnings = _apply_waivers(
        _policy(expires=expires, created=created), [result], date(2026, 10, 31)
    )
    assert result.outcome is Outcome.UNKNOWN
    assert result.checks[0].waived_unknown is False
    assert not any("WAIVED_UNKNOWN:" in w for w in warnings)


def test_waived_failure_does_not_claim_unknown():
    result = _result(Outcome.FAIL)
    warnings = _apply_waivers(_policy(), [result], date(2026, 10, 31))
    assert result.checks[0].outcome is Outcome.WAIVED
    assert result.checks[0].waived_unknown is False
    assert not any("WAIVED_UNKNOWN:" in w for w in warnings)


def test_unmatched_unknown_waiver_does_not_mark_other_checks():
    result = _result(Outcome.UNKNOWN, check="job_success")
    warnings = _apply_waivers(_policy(), [result], date(2026, 10, 31))
    assert result.outcome is Outcome.UNKNOWN
    assert result.checks[0].waived_unknown is False
    assert not any("WAIVED_UNKNOWN:" in w for w in warnings)
