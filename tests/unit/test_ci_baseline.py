"""Regression coverage for the machine-readable CI quality baseline."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/ci_baseline.py"
_spec = importlib.util.spec_from_file_location("ci_baseline", SCRIPT)
assert _spec is not None and _spec.loader is not None
baseline = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(baseline)


def _reports(
    tmp_path: Path, *, passed: int = 1075, skipped: int = 1, missed: int = 96
) -> tuple[Path, Path]:
    junit = tmp_path / "junit.xml"
    junit.write_text(
        f'<testsuites><testsuite tests="{passed + skipped}" failures="0" '
        f'errors="0" skipped="{skipped}" time="69.3" /></testsuites>',
        encoding="utf-8",
    )
    cov = tmp_path / "coverage.json"
    cov.write_text(
        json.dumps(
            {
                "totals": {
                    "percent_covered": 94.42,
                    "num_branches": 1388,
                    "missing_branches": missed,
                }
            }
        ),
        encoding="utf-8",
    )
    return junit, cov


def test_valid_test_metrics_and_timing(tmp_path):
    junit, coverage = _reports(tmp_path)
    result = baseline.test_metrics(junit, coverage)
    assert result["passed"] == 1075
    assert result["skipped"] == 1
    assert result["suite_seconds"] == 69.3
    assert 93 < result["branch_coverage_percent"] < 94


@pytest.mark.parametrize("kwargs", [{"passed": 1074}, {"skipped": 2}, {"missed": 200}])
def test_test_regression_fails_closed(tmp_path, kwargs):
    junit, coverage = _reports(tmp_path, **kwargs)
    with pytest.raises(baseline.BaselineError):
        baseline.test_metrics(junit, coverage)


def test_missing_branch_data_is_rejected(tmp_path):
    junit, coverage = _reports(tmp_path)
    coverage.write_text('{"totals": {"percent_covered": 95}}', encoding="utf-8")
    with pytest.raises(KeyError):
        baseline.test_metrics(junit, coverage)


def test_non_finite_coverage_is_rejected(tmp_path):
    junit, coverage = _reports(tmp_path)
    text = coverage.read_text(encoding="utf-8").replace("94.42", "NaN")
    coverage.write_text(text, encoding="utf-8")
    with pytest.raises(baseline.BaselineError):
        baseline.test_metrics(junit, coverage)


def test_package_manifest_sizes_and_checksums(tmp_path):
    (tmp_path / "scanproof-0.1.0-py3-none-any.whl").write_bytes(b"wheel")
    (tmp_path / "scanproof-0.1.0.tar.gz").write_bytes(b"source")
    metrics = baseline.artifact_metrics(tmp_path)
    assert [x["bytes"] for x in metrics["artifacts"]] == [5, 6]
    assert all(len(x["sha256"]) == 64 for x in metrics["artifacts"])


def test_missing_and_oversized_package_rejected(tmp_path):
    with pytest.raises(baseline.BaselineError):
        baseline.artifact_metrics(tmp_path)
    (tmp_path / "scanproof-0.1.0-py3-none-any.whl").write_bytes(b"a" * (2 * 1024 * 1024 + 1))
    (tmp_path / "scanproof-0.1.0.tar.gz").write_bytes(b"x")
    with pytest.raises(baseline.BaselineError):
        baseline.artifact_metrics(tmp_path)


def test_cli_refuses_missing_input(tmp_path):
    assert baseline.main(["tests", "--output", str(tmp_path / "out.json")]) == 1
    assert not (tmp_path / "out.json").exists()
