# CI quality baseline and regression gates

**Status:** pre-alpha engineering measurements, not a production-readiness or protected-release-gate certification. Implemented in [#85](https://github.com/abdelrahman-eladwy/scanproof/issues/85). The source of truth is the current CI workflow and its uploaded per-run JSON, not numbers copied from this page.

## Historical reference (2026-10-28)

Core commit `4b3656474c8e28da31a41ed3803221061f3b3e83`, [successful CI #40681641878](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40681641878):

| Metric | Observed | Enforcement introduced here |
|---|---|---|
| Python 3.12 and 3.13 tests | 1,075 passed, 1 skipped **per version** | At least 1,075 **passing**, at most 1 skipped; tests removed or newly skipped are detected |
| Combined line-and-branch coverage | 94.42% | At least 90%, plus an **independent** branch-only coverage floor of 90% |
| Branch-only coverage | Not separately captured in the historical console output. First structured PR #86 run: 1,270 of 1,388 branches = **91.50%** | Explicitly measured from coverage JSON; nonempty branch denominator |
| Full pytest suite wall time | About 69–71 seconds per supported Python version | Recorded for each run, **not a time limit**; shared hosted runners vary |
| Installed wheel / non-root Docker full suites | 1,075 passed, 1 skipped each | Both remain mandatory green CI jobs, with tests guarded against source imports |
| Dependency floors | Core and attestation lowest-deps jobs green | Both remain mandatory; CI logs are evidence until added to metrics |
| Distributions | Wheel and source distribution built in package CI | Record exact bytes and SHA256 for each; reject missing, empty, duplicate, oversized output |

**Careful:** the 96 shown in the historical coverage terminal table is the *partially covered branches* count (`BrPart`), not the *missing branches* count. JSON in the first PR #86 run reported 118 missing of 1,388; do not infer branch-only coverage from `BrPart`.

The 90% combined coverage gate was already present. This change adds *separate branch coverage*, a count/skip floor and retained structured evidence.

## Evidence produced by each PR and main run

- `ci-quality-3.12` and `ci-quality-3.13` contain `ci-baseline.json`, `junit.xml`, and `coverage.json` (generated directly by the tests). Counts are read from JUnit and coverage percentages from coverage JSON, not scraped from colored logs.
- `ci-package-quality` contains `ci-package.json` with file names, byte sizes, SHA256, run SHA and elapsed package-job time. The wheel cap of 2 MiB and source archive cap of 16 MiB are **conservative upper bounds**, not recorded historical sizes. Tighten them after confirming a stable measured baseline.
- Each reporter writes a job summary and fails CI if evidence is missing, malformed, or below threshold. `ci_elapsed_seconds` is time since a dedicated start step, covering installation/test/build steps but **not** runner queue time or all GitHub job setup/cleanup. `suite_seconds` is pytest's JUnit duration.
- `scripts/test_installed.sh` continues to exclude `src/`; it now copies the CI-only measurement helper so its own unit tests also execute with the installed wheel/container.

A passing metric gate is **not** independent proof that the provider will block deployment if a developer removes or changes the workflow. That requires sacrificial protected GitHub/GitLab settings and malicious-bypass acceptance tests in [#25](https://github.com/abdelrahman-eladwy/scanproof/issues/25), [#26](https://github.com/abdelrahman-eladwy/scanproof/issues/26) and [#45](https://github.com/abdelrahman-eladwy/scanproof/issues/45).

## Maintenance

Only raise or lower floors in a reviewed PR with a linked issue, before/after measurements, the reason and an explicit security impact review. Do not reduce a test count to hide a regression. Never equate high coverage with absence of a false VERIFIED path; continue adding targeted adversarial regression tests and validating live contracts.
