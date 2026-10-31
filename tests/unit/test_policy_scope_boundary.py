"""Regression: extracted scope evaluation preserves report decisions and public imports."""

from types import SimpleNamespace

import pytest

from scanproof.evidence.models import ScanEvidence
from scanproof.policy import engine, scope
from scanproof.policy.results import CheckResult, Outcome, _r


def _evidence(*, results_reported=True, files=None, paths=None):
    return ScanEvidence.model_construct(
        results_reported=results_reported,
        scope=SimpleNamespace(
            files_scanned=files,
            components=None,
            resources=None,
            endpoints=None,
            scanned_paths=paths,
        ),
    )


@pytest.mark.parametrize(
    ("reported", "files", "paths", "expected_outcome", "expected_code"),
    [
        (False, 5, ["a.py"], Outcome.FAIL, "SCAN_RESULTS_MISSING"),
        (True, 0, [], Outcome.FAIL, "SCAN_SCOPE_EMPTY"),
        (True, -1, None, Outcome.FAIL, "SCAN_SCOPE_INVALID"),
        (True, 0, ["a.py"], Outcome.UNKNOWN, "SCAN_SCOPE_CONFLICT"),
        (True, 1, None, Outcome.PASS, "REPORTED_SCOPE_PRESENT"),
        (True, None, [], Outcome.FAIL, "SCAN_SCOPE_EMPTY"),
        (True, None, ["a.py"], Outcome.PASS, "REPORTED_SCOPE_PRESENT"),
        (True, None, [" "], Outcome.FAIL, "SCAN_SCOPE_INVALID"),
        (True, None, None, Outcome.UNKNOWN, "SCAN_SCOPE_UNKNOWN"),
    ],
)
def test_scanner_scope_decisions(reported, files, paths, expected_outcome, expected_code):
    result = engine._reported_scope(
        _evidence(results_reported=reported, files=files, paths=paths)
    )
    assert result.check == "reported_scope"
    assert result.outcome is expected_outcome
    assert result.code == expected_code
    assert result.waived_unknown is False
    assert result.model_dump(mode="json")["outcome"] == expected_outcome.value


def test_extracted_functions_preserve_public_engine_imports():
    assert engine._reported_scope is scope._reported_scope
    assert engine._r is _r
    assert _r("test", Outcome.UNKNOWN, "X", "message") == CheckResult(
        check="test", outcome=Outcome.UNKNOWN, code="X", message="message"
    )
