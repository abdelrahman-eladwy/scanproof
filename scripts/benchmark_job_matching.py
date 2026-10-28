"""Measure the bounded 2,000-job / 50-way matching fixture for Phase 3 (#46).

This measures only in-memory job selection; it is not a verification SLO,
network/provider benchmark, or independent platform-enforcement proof.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import time
import tracemalloc
from pathlib import Path

from scanproof.evidence.collector import match_jobs
from scanproof.models import InspectedJob, Job, JobStatus

COPIES = [f"svc-{i:02d}" for i in range(20)]
INSTANCES = [f"lang-{i:02d}" for i in range(50)]


def _inventory() -> list[InspectedJob]:
    names = [f"{copy} > sast: [{label}]" for copy in COPIES for label in INSTANCES]
    names.extend(f"unrelated-{i:04d}" for i in range(1000))
    return [
        InspectedJob(
            name=name,
            stage=None,
            latest=Job(id=i, name=name, status=JobStatus.SUCCESS, commit_sha="a" * 40),
            attempt_ids=[i],
            commit_matches_pipeline=True,
        )
        for i, name in enumerate(names, 1)
    ]


def _measure(iterations: int) -> dict[str, object]:
    tracemalloc.start()
    try:
        jobs = _inventory()
        if len(jobs) != 2000:
            raise ValueError("Fixture changed: expected exactly 2000 jobs")

        def run() -> None:
            match = match_jobs(jobs, "sast", instances=INSTANCES, copies=COPIES)
            if (
                len(match.jobs) != 1000
                or match.missing
                or match.missing_declared
                or match.missing_copies
                or match.undeclared_copies
            ):
                raise ValueError("Large-pipeline matching correctness regression")

        for _ in range(3):
            run()
        durations = []
        for _ in range(iterations):
            start = time.perf_counter()
            run()
            durations.append(time.perf_counter() - start)
        peak_bytes = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    durations.sort()
    return {
        "kind": "job-matching-microbenchmark",
        "commit": os.environ.get("GITHUB_SHA"),
        "fixture_jobs": 2000,
        "matrix_copies": len(COPIES),
        "matrix_legs_per_copy": len(INSTANCES),
        "matching_jobs": 1000,
        "iterations": iterations,
        "median_seconds": round(statistics.median(durations), 6),
        "p95_seconds": round(durations[math.ceil(0.95 * iterations) - 1], 6),
        "max_seconds": round(max(durations), 6),
        "tracemalloc_peak_bytes": peak_bytes,
        "scope": "in-memory matching only; excludes provider API, artifacts and policy evaluation",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not 10 <= args.iterations <= 200:
        parser.error("iterations must be between 10 and 200")
    metrics = _measure(args.iterations)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
