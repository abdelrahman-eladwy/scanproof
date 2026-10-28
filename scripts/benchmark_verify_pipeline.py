"""End-to-end verification benchmark for Phase 3 (#46).

Runs the full `verify_pipeline` path (pipeline + paginated jobs API, artifact
downloads, scanner parsing, policy evaluation) against an in-process GitLab
double: 100 jobs over 5 API pages, 10 required reports (5 Semgrep, 5 Trivy).

Every measured run must be VERIFIED, or the script exits non-zero. Network
latency, provider rate limits and real artifact transfer are NOT measured.
This is an engineering measurement, not an accepted SLO or platform-
enforcement proof. Run from a repository checkout with dev dependencies.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import resource
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import respx  # noqa: E402

from scanproof.connectors.gitlab import GitLabConnector  # noqa: E402
from scanproof.policy.engine import Decision  # noqa: E402
from scanproof.policy.models import Policy  # noqa: E402
from scanproof.verification import verify_pipeline  # noqa: E402
from tests.conftest import TOKEN  # noqa: E402
from tests.fake_gitlab import FakeGitLab  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
BASE = "https://gitlab.example.com"

DIGEST = "sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"
TOTAL_JOBS = 100
SEMGREP_JOBS = 5
TRIVY_JOBS = 5
JOB_PAGES = 5
# Proposed (not accepted) budgets from docs/development/production-readiness.md.
PROPOSED_P95_SECONDS = 30.0
PROPOSED_RSS_MIB = 512.0


def policy() -> Policy:
    reqs = [
        {
            "id": f"SAST-{i:03d}",
            "tool": "semgrep",
            "job_name": f"semgrep-sast-{i}",
            "report_path": "semgrep.json",
            "checks": {
                "scanner_errors_allowed": 0,
                "minimum_scanned_files": 1,
                "required_paths": ["examples/gitlab-ci/sample-app/"],
            },
        }
        for i in range(SEMGREP_JOBS)
    ] + [
        {
            "id": f"CONTAINER-{i:03d}",
            "tool": "trivy",
            "job_name": f"trivy-image-{i}",
            "report_path": "trivy.json",
            "checks": {"image_digest_must_match": DIGEST},
        }
        for i in range(TRIVY_JOBS)
    ]
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "metadata": {"name": "benchmark-100-jobs"},
            "project": {"provider": "gitlab", "id": "123"},
            "requirements": reqs,
        }
    )


def install(router: respx.MockRouter, *, drop_report: bool = False) -> int:
    semgrep = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()
    trivy = (FIXTURES / "trivy/trivy-python.json").read_bytes()
    router.get(
        url__regex=r".*/api/v4/projects/[^/]+/pipelines/\d+/bridges", name="bridges"
    ).respond(json=[])
    gl = FakeGitLab(router, jobs_pages=JOB_PAGES)
    jid = 10_000
    for i in range(SEMGREP_JOBS):
        files = {} if (drop_report and i == 0) else {"semgrep.json": semgrep}
        gl.job(jid := jid + 1, f"semgrep-sast-{i}", files=files)
    for i in range(TRIVY_JOBS):
        gl.job(jid := jid + 1, f"trivy-image-{i}", files={"trivy.json": trivy})
    for i in range(TOTAL_JOBS - SEMGREP_JOBS - TRIVY_JOBS):
        gl.job(jid := jid + 1, f"build-{i:03d}", stage="build")
    gl.install()
    return len(gl.root.jobs)


def run_once(pol: Policy, *, drop_report: bool = False):
    with respx.mock(assert_all_called=False) as router:
        n_jobs = install(router, drop_report=drop_report)
        conn = GitLabConnector(BASE, TOKEN, sleep=lambda _s: None, max_retries=0)
        try:
            start = time.perf_counter()
            report = verify_pipeline(conn, pol, instance_url=BASE, project="123", pipeline_id=1042)
            elapsed = time.perf_counter() - start
        finally:
            conn.close()
        return report, elapsed, n_jobs, len(router.calls)


def nearest_rank(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(pct / 100 * len(ordered)) - 1)]


def peak_rss_mib() -> float:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB, macOS reports bytes.
    return raw / (1024 * 1024) if sys.platform == "darwin" else raw / 1024


def measure(iterations: int, warmups: int) -> dict[str, object]:
    pol = policy()
    for _ in range(warmups):
        report, _, _, _ = run_once(pol)
        if report.decision is not Decision.VERIFIED:
            raise SystemExit(f"warmup not VERIFIED: {report.decision}")

    tracemalloc.start()
    samples: list[float] = []
    calls = n_jobs = 0
    try:
        for _ in range(iterations):
            report, elapsed, n_jobs, calls = run_once(pol)
            if report.decision is not Decision.VERIFIED or report.exit_code != 0:
                raise SystemExit(f"measured run not VERIFIED: {report.decision}")
            samples.append(elapsed)
        _, traced_peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    negative, _, _, _ = run_once(pol, drop_report=True)
    if negative.decision is Decision.VERIFIED:
        raise SystemExit("negative control (missing report) was VERIFIED")

    p95 = nearest_rank(samples, 95)
    rss = peak_rss_mib()
    return {
        "scope": "in-process GitLab double; excludes network, rate limits, real transfer",
        "fixture": {
            "jobs": n_jobs,
            "job_api_pages": JOB_PAGES,
            "required_reports": SEMGREP_JOBS + TRIVY_JOBS,
            "http_calls_per_run": calls,
        },
        "python": platform.python_version(),
        "iterations": iterations,
        "warmups": warmups,
        "seconds": {
            "median": round(statistics.median(samples), 6),
            "p95_nearest_rank": round(p95, 6),
            "max": round(max(samples), 6),
        },
        "peak_rss_mib": round(rss, 1),
        "peak_traced_python_mib": round(traced_peak / (1024 * 1024), 2),
        "every_run_verified": True,
        "negative_control_decision": negative.decision.value,
        "proposed_budgets_not_accepted": {
            "p95_seconds": PROPOSED_P95_SECONDS,
            "rss_mib": PROPOSED_RSS_MIB,
            "p95_within": p95 < PROPOSED_P95_SECONDS,
            "rss_within": rss < PROPOSED_RSS_MIB,
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--iterations", type=int, default=30)
    ap.add_argument("--warmups", type=int, default=3)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args(argv)
    if args.iterations < 1 or args.warmups < 0:
        ap.error("--iterations must be >= 1 and --warmups >= 0")
    result = measure(args.iterations, args.warmups)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    raise SystemExit(main())
