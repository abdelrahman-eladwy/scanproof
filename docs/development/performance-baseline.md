# Large-pipeline matching measurement (Phase 3, #46)

**Scope:** in-memory job-name selection only. This is an engineering microbenchmark,
**not** a CI-provider, artifact-transfer, cryptographic verification, full-policy,
or protected-deployment performance qualification. No release SLO has been accepted.

## Reproducible fixture and correctness checks

`tests/unit/test_large_pipeline_matching.py` exercises a 2,000-job inventory:
20 downstream copy paths each with 50 GitLab-style matrix legs (1,000 required
jobs), plus 1,000 unrelated jobs. The regression checks that all 1,000 match;
removing one declared matrix leg remains observable; qualified names never include
unrelated copies. A separate 2,000-leg parallel case proves that a missing index
is still BLOCKED by a bounded diagnostic rather than silently skipped.

Run the matching-only benchmark from the repository with ScanProof installed:

```sh
python scripts/benchmark_job_matching.py --iterations 30 \
  --output build/job-matching-benchmark.json
```

Both Python 3.12 and 3.13 core CI test jobs now emit a
`job-matching-benchmark.json` alongside their JUnit and coverage artifacts,
using the same fixed fixture. The script runs three warmups and 30 measured
iterations by default, records median, nearest-rank p95, maximum, and peak Python
`tracemalloc` allocation. It fails if the supposedly complete fixture has
missing declared legs or copies. Compare measurements across CI runs with
runner/Python version in mind; a single hosted-runner p95 is not a deployment SLO.
The memory metric excludes native allocator overhead and system RSS.

## End-to-end verify measurement (in-process provider double)

`scripts/benchmark_verify_pipeline.py` runs the full `verify_pipeline` path —
pipeline and paginated jobs API, bridges, artifact downloads, Semgrep/Trivy
parsing and policy evaluation — against the respx GitLab double used by the
unit tests. Fixture: 100 jobs over 5 job-API pages, 10 required reports
(5 Semgrep, 5 Trivy), exactly 17 HTTP calls per run. Every measured run must be
VERIFIED and a missing-report negative control must not be, or the script exits
non-zero. It records median, nearest-rank p95, maximum, process peak RSS and
peak traced Python allocations; both core CI test jobs upload
`verify-pipeline-benchmark.json`.

```sh
python scripts/benchmark_verify_pipeline.py --iterations 30 \
  --output build/verify-pipeline-benchmark.json
```

First local measurement (Python 3.13, 10 iterations): median ≈0.055 s,
p95 ≈0.069 s, peak RSS ≈60 MiB. These are far inside the proposed budgets but
**exclude network latency, provider rate-limit waits, real artifact sizes,
attestation verification and concurrency**, so they do not satisfy the Phase 3
SLO checkbox by themselves. Regression: `tests/unit/test_verify_pipeline_benchmark.py`.

## Unmet acceptance criteria

The matching microbenchmark and the in-process verify measurement above cover
neither real provider API latency/retries/429 behavior nor attestation
verification, real-size artifacts, concurrency, or provider-backed 2,000-job
pipelines. The Phase 3 target (such as p95 under 30 seconds for a
representative 100-job/10-report pipeline and memory under 512 MiB) is only a
proposal until full-pipeline measurements, tolerances and owner sign-off exist.

Before closing [#46](https://github.com/abdelrahman-eladwy/scanproof/issues/46),
add representative provider-backed 2,000-job fixtures, failure injection and
operational runbooks. **Do not interpret this microbenchmark as completed
Phase 3 acceptance or production readiness.**
