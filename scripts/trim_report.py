"""Shrink large real SARIF / CycloneDX reports for use as test fixtures.

SARIF: keeps at most N results per run and only the rules they reference (ruleIndex remapped).
CycloneDX: keeps at most N top-level components and drops the dependency graph.
The original counts are recorded under "_scanproof_fixture" so reviewers can see what changed.

    python scripts/trim_report.py sarif in.sarif out.sarif [--keep 30]
    python scripts/trim_report.py cyclonedx in.cdx.json out.cdx.json [--keep 30]
"""

from __future__ import annotations

import argparse
import json


def trim_sarif(log: dict, keep: int) -> dict:
    original = []
    for run in log["runs"]:
        results = run.get("results") or []
        original.append(len(results))
        kept = results[:keep]
        driver = run["tool"].get("driver") or {}
        rules = driver.get("rules") or []
        used = sorted(
            {r["ruleIndex"] for r in kept if isinstance(r.get("ruleIndex"), int)}
            | {
                i
                for i, rule in enumerate(rules)
                if rule.get("id") in {r.get("ruleId") for r in kept}
            }
        )
        remap = {old: new for new, old in enumerate(used)}
        driver["rules"] = [rules[i] for i in used]
        for r in kept:
            if isinstance(r.get("ruleIndex"), int):
                r["ruleIndex"] = remap[r["ruleIndex"]]
        if "results" in run:
            run["results"] = kept
    log["_scanproof_fixture"] = {
        "trimmed": True,
        "kept_results_per_run": keep,
        "original_results_per_run": original,
    }
    return log


def trim_cyclonedx(bom: dict, keep: int) -> dict:
    original = len(bom.get("components") or [])
    bom["components"] = (bom.get("components") or [])[:keep]
    bom.pop("dependencies", None)
    bom["_scanproof_fixture"] = {
        "trimmed": True,
        "kept_components": keep,
        "original_top_level_components": original,
    }
    return bom


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["sarif", "cyclonedx"])
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--keep", type=int, default=30)
    a = ap.parse_args()
    with open(a.src, encoding="utf-8") as f:
        data = json.load(f)
    data = trim_sarif(data, a.keep) if a.kind == "sarif" else trim_cyclonedx(data, a.keep)
    with open(a.dst, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
