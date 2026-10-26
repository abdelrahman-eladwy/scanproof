"""Shrink a real Trivy JSON report for use as a test fixture.

Keeps the structure, metadata and per-severity counts ScanProof relies on; drops the
package inventory and keeps at most N vulnerabilities per result. Records what was
trimmed under "_scanproof_fixture" so tests and reviewers can see it is not pristine.

    python scripts/trim_trivy_report.py in.json out.json [--keep 10]
"""

from __future__ import annotations

import argparse
import json
from collections import Counter


def trim(report: dict, keep: int) -> dict:
    original = Counter()
    for result in report.get("Results") or []:
        result.pop("Packages", None)
        vulns = result.get("Vulnerabilities") or []
        original.update(v.get("Severity", "UNKNOWN") for v in vulns)
        if vulns:
            result["Vulnerabilities"] = vulns[:keep]
    report.get("Metadata", {}).pop("Layers", None)
    report["_scanproof_fixture"] = {
        "trimmed": True,
        "kept_vulnerabilities_per_result": keep,
        "original_severity_counts": dict(sorted(original.items())),
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("src")
    parser.add_argument("dst")
    parser.add_argument("--keep", type=int, default=10)
    args = parser.parse_args()
    with open(args.src, encoding="utf-8") as f:
        report = json.load(f)
    with open(args.dst, "w", encoding="utf-8") as f:
        json.dump(trim(report, args.keep), f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
