"""Record CI quality evidence and reject regressions, not certify deployment gates.

The standard-library reporter consumes pytest JUnit and coverage JSON, or
built distribution files. It fails closed when evidence is missing or invalid.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

MIN_PASSED = 1075  # 2026-10-28 main: 1075 passed, 1 skipped
MAX_SKIPPED = 1
MIN_COVERAGE = 90.0
MIN_BRANCH_COVERAGE = 90.0
MAX_WHEEL_BYTES = 2 * 1024 * 1024
MAX_SDIST_BYTES = 16 * 1024 * 1024


class BaselineError(ValueError):
    """Required measurement missing or below the agreed threshold."""


def _elapsed() -> float | None:
    start = os.environ.get("SCANPROOF_CI_START_EPOCH")
    if start is None:
        return None
    seconds = time.time() - float(start)
    if seconds < 0:
        raise BaselineError("CI start time is in the future")
    return round(seconds, 2)


def test_metrics(junit_path: Path, coverage_path: Path) -> dict[str, object]:
    root = ET.parse(junit_path).getroot()  # noqa: S314 (CI-generated JUnit)
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    if not suites:
        raise BaselineError("JUnit XML has no test suites")
    counts = {
        name: sum(int(suite.attrib[name]) for suite in suites)
        for name in ("tests", "failures", "errors", "skipped")
    }
    passed = counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
    if counts["tests"] <= 0 or passed < 0:
        raise BaselineError("JUnit XML has invalid test counts")
    if counts["failures"] or counts["errors"]:
        raise BaselineError("JUnit XML reports failing or errored tests")
    if passed < MIN_PASSED or counts["skipped"] > MAX_SKIPPED:
        raise BaselineError(
            f"test baseline regression: {passed} passed, {counts['skipped']} skipped; "
            f"require >= {MIN_PASSED} passed and <= {MAX_SKIPPED} skipped"
        )

    totals = json.loads(coverage_path.read_text(encoding="utf-8"))["totals"]
    overall = float(totals["percent_covered"])
    branches = int(totals["num_branches"])
    missed = int(totals["missing_branches"])
    if not math.isfinite(overall) or not 0 <= overall <= 100:
        raise BaselineError("coverage has invalid overall percent")
    if branches <= 0 or not 0 <= missed <= branches:
        raise BaselineError("coverage data lacks valid branch measurements")
    branch_percent = 100.0 * (branches - missed) / branches
    if overall < MIN_COVERAGE or branch_percent < MIN_BRANCH_COVERAGE:
        raise BaselineError(
            f"coverage regression: total {overall:.2f}%, branches {branch_percent:.2f}%; "
            f"require both >= {MIN_COVERAGE:.0f}%"
        )
    return {
        "kind": "tests",
        "tested": counts["tests"],
        "passed": passed,
        "skipped": counts["skipped"],
        "failures": counts["failures"],
        "errors": counts["errors"],
        "suite_seconds": round(sum(float(suite.attrib["time"]) for suite in suites), 2),
        "overall_coverage_percent": round(overall, 2),
        "branch_coverage_percent": round(branch_percent, 2),
        "branches": branches,
        "missed_branches": missed,
    }


def artifact_metrics(dist: Path) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for extension, limit in (("*.whl", MAX_WHEEL_BYTES), ("*.tar.gz", MAX_SDIST_BYTES)):
        found = sorted(dist.glob(extension))
        if len(found) != 1 or not found[0].name.startswith("scanproof-"):
            raise BaselineError(f"expected exactly one ScanProof artifact matching {extension}")
        path = found[0]
        size = path.stat().st_size
        if size == 0 or size > limit:
            raise BaselineError(f"artifact {path.name} size {size} outside 1..{limit} bytes")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        results.append({"name": path.name, "bytes": size, "sha256": digest})
    return {"kind": "artifacts", "artifacts": results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["tests", "artifacts"])
    parser.add_argument("--junit", type=Path)
    parser.add_argument("--coverage", type=Path)
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.kind == "tests":
            if args.junit is None or args.coverage is None:
                raise BaselineError("tests need --junit and --coverage")
            metrics = test_metrics(args.junit, args.coverage)
        else:
            if args.dist is None:
                raise BaselineError("artifacts need --dist")
            metrics = artifact_metrics(args.dist)
        metrics.update({"commit": os.environ.get("GITHUB_SHA"), "ci_elapsed_seconds": _elapsed()})
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(metrics, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with Path(summary).open("a", encoding="utf-8") as handle:
                handle.write(f"### ScanProof CI baseline — {args.kind}\n\n")
                handle.write(json.dumps(metrics, sort_keys=True, indent=2) + "\n")
        print(json.dumps(metrics, sort_keys=True))
        return 0
    except (BaselineError, OSError, ValueError, KeyError, ET.ParseError) as exc:
        print(f"CI baseline FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
