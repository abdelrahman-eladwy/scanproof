"""Cross-platform benchmark import and RSS reporting regressions."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/benchmark_verify_pipeline.py"
pytestmark = pytest.mark.skipif(not SCRIPT.is_file(), reason="benchmark not packaged in wheel")


def _module():
    spec = importlib.util.spec_from_file_location("benchmark_verify_pipeline", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_windows_without_resource_reports_unknown_rss(monkeypatch) -> None:
    benchmark = _module()
    monkeypatch.setattr(benchmark, "resource", None)
    assert benchmark.peak_rss_mib() is None
    result = benchmark.measure(iterations=1, warmups=0)
    assert result["every_run_verified"] is True
    assert result["peak_rss_mib"] is None
    assert result["proposed_budgets_not_accepted"]["rss_within"] is None
    assert result["peak_traced_python_mib"] >= 0
