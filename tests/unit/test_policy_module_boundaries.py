"""Regression: policy module split preserves public engine identities and waiver behavior."""

from datetime import date

from scanproof.policy import engine, results, waivers
from scanproof.policy.models import Policy, Waiver


def test_engine_still_exports_exact_result_types_and_aggregation():
    assert engine.Outcome is results.Outcome
    assert engine.Decision is results.Decision
    assert engine.CheckResult is results.CheckResult
    assert engine.RequirementInput is results.RequirementInput
    assert engine.RequirementResult is results.RequirementResult
    assert engine.Evaluation is results.Evaluation
    assert engine.combine is results.combine
    assert (
        engine.combine([engine.Outcome.UNKNOWN, engine.Outcome.WAIVED])
        is engine.Outcome.UNKNOWN
    )


def test_waiver_function_identity_and_unknown_provenance():
    assert engine._apply_waivers is waivers._apply_waivers
    check = engine.CheckResult(
        check="report",
        outcome=engine.Outcome.UNKNOWN,
        code="EVIDENCE_UNAVAILABLE",
        message="API unavailable",
    )
    result = engine.RequirementResult(
        id="sast",
        description=None,
        tool="semgrep",
        job_name="scan",
        job_id=1,
        outcome=engine.Outcome.UNKNOWN,
        checks=[check],
    )
    waiver = Waiver(
        requirement="sast",
        check="report",
        code="EVIDENCE_UNAVAILABLE",
        reason="Risk tracked in release issue",
        approved_by="security",
        expires=date(2026, 12, 31),
    )
    policy = Policy.model_construct(waivers=[waiver])
    warnings = engine._apply_waivers(policy, [result], date(2026, 10, 31))
    assert result.checks[0].outcome is engine.Outcome.WAIVED
    assert result.checks[0].waived_unknown is True
    assert any("WAIVED_UNKNOWN:" in warning for warning in warnings)
