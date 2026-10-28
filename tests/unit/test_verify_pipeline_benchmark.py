"""Phase 3 (#46): the end-to-end verify benchmark fixture must stay honest.

The benchmark is only meaningful if its fixture is exactly what it claims
(100 jobs, 5 job-API pages, 10 reports) and every measured run is a real
VERIFIED with a non-VERIFIED negative control.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from scanproof.policy.engine import Decision

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/benchmark_verify_pipeline.py"
_spec = importlib.util.spec_from_file_location("benchmark_verify_pipeline", SCRIPT)
assert _spec is not None and _spec.loader is not None
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)


def test_fixture_is_verified_with_exact_request_accounting() -> None:
    report, elapsed, n_jobs, calls = bench.run_once(bench.policy())
    assert report.decision is Decision.VERIFIED
    assert report.exit_code == 0
    assert n_jobs == bench.TOTAL_JOBS == 100
    # pipeline + paginated jobs + bridges + one download per required report
    assert calls == 1 + bench.JOB_PAGES + 1 + bench.SEMGREP_JOBS + bench.TRIVY_JOBS
    assert elapsed > 0


def test_missing_report_negative_control_is_not_verified() -> None:
    report, _, _, _ = bench.run_once(bench.policy(), drop_report=True)
    assert report.decision is not Decision.VERIFIED
    assert report.exit_code != 0


def test_benchmark_output_is_complete_and_bounded(tmp_path: Path) -> None:
    out = tmp_path / "verify-benchmark.json"
    assert bench.main(["--iterations", "2", "--warmups", "0", "--output", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["every_run_verified"] is True
    assert data["negative_control_decision"] != "VERIFIED"
    assert data["fixture"] == {
        "jobs": 100,
        "job_api_pages": 5,
        "required_reports": 10,
        "http_calls_per_run": 17,
    }
    s = data["seconds"]
    assert 0 < s["median"] <= s["max"] and s["p95_nearest_rank"] <= s["max"]
    assert data["peak_rss_mib"] > 0
    assert "excludes network" in data["scope"]


@pytest.mark.parametrize("argv", [["--iterations", "0"], ["--warmups", "-1"]])
def test_invalid_arguments_are_usage_errors(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        bench.main(argv)
    assert exc.value.code == 2


def test_nearest_rank_p95() -> None:
    assert bench.nearest_rank([float(i) for i in range(1, 21)], 95) == 19.0
    assert bench.nearest_rank([5.0], 95) == 5.0
