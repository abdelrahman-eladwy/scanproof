# Complex scenarios: what ScanProof does, and how we know

Each row is an automated test. "Live" rows are also checked against real platform behaviour:
GitHub rows run in `.github/workflows/github-contract.yml` (ScanProof verifies its own run), and
GitLab rows replay real gitlab.com API responses saved in `tests/fixtures/gitlab-real/`.

## GitLab (`tests/unit/test_complex_gitlab.py`)

| Scenario | Decision | Code | Source |
|---|---|---|---|
| Monorepo: 3 child pipelines, one service's scan failed under `allow_failure` | BLOCKED | `FAILURE_MASKED_BY_ALLOW_FAILURE` | test |
| Same monorepo, all clean | VERIFIED (findings summed over instances) | | test |
| Child pipeline the token can't read; required job not found elsewhere | INDETERMINATE | `JOB_MAYBE_IN_UNREADABLE_PIPELINE` | test + real gitlab-runner |
| Trigger job that never started a pipeline | BLOCKED | `REQUIRED_JOB_ABSENT` (+ warning) | test |
| Nested children, pinned with `trigger > job` | as the pinned job | | test + real gitlab-org/gitlab |
| Multi-project downstream on another repo's commit | BLOCKED; VERIFIED with `same_commit: false` | `COMMIT_MISMATCH` | test + real gitlab-runner |
| `parallel: 3` with instance `2/3` missing | BLOCKED | `REQUIRED_JOB_ABSENT` on `job_present [semgrep 2/3]` | test |
| `parallel:` with one instance retried | latest try judged per instance | | test |
| `parallel: matrix:` instance with no report | BLOCKED | `REPORT_MISSING` | test |
| Gate runs before the scan finishes | INDETERMINATE | `REPORT_NOT_YET_AVAILABLE` | test |
| Six requirements, six different faults, one pipeline | BLOCKED, each fault reported separately | | test |
| MR pipeline, every requirement `applies_to: main` | INDETERMINATE (or VERIFIED with `on_nothing_applicable: allow`) | | test |
| Artifact download drops mid-transfer once | retried, VERIFIED | | test |
| Download keeps dropping | INDETERMINATE | `EVIDENCE_UNAVAILABLE` | test |
| 429 during job pagination | retried after `Retry-After` | | test |
| 2,000 jobs over 21 pages, 50-way parallel scan | correct decision in under 10 s | | test |

## GitHub Actions (`tests/unit/test_complex_github.py`)

| Scenario | Decision | Code | Source |
|---|---|---|---|
| Matrix job, `go` instance masked by step `continue-on-error` | BLOCKED | `job_success [matrix-sast (go)]` | test + live |
| Masked failure after 150 warnings | BLOCKED | `FAILURE_MASKED_BY_ALLOW_FAILURE` | test + live |
| Failure annotation only on a later page | BLOCKED | | test (see note) |
| More annotation pages than ScanProof reads (20) | INDETERMINATE | `STEP_MASKING_UNKNOWN` | test |
| Annotations page 2 returns 403 | INDETERMINATE | | test |
| Job inside a reusable workflow (`caller / callee-sast`) | VERIFIED via `job_name: callee-sast` | | test + live |
| Re-run: attempt 1 failed, attempt 2 passed | VERIFIED, attempt 2 judged | | test |
| Same artifact name uploaded twice | newest artifact used | | test |
| Gate inside a still-running workflow | INDETERMINATE | `JOB_NOT_FINISHED` | test |
| Artifact bytes don't match GitHub's digest | BLOCKED | digest mismatch | test + live |

Note on annotations: in live run 40382339477 GitHub kept 10 of the 150 warnings one step
produced; it caps annotations per step and per job. So on github.com today the failure annotation
fits on the first page. ScanProof still reads every page, and treats an unfinished read as UNKNOWN,
in case GHES or future limits differ.

## Jenkins, live (`platforms-contract.yml`, `tests/unit/test_jenkins.py`)

A real Jenkins 2.580.1 runs each pipeline; ScanProof then verifies it over the REST API.

| Pipeline | Jenkins shows | Decision | Source |
|---|---|---|---|
| plain scan | SUCCESS | VERIFIED | live + test |
| `catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE')` | build SUCCESS, stage failed | BLOCKED `FAILURE_MASKED_BY_ALLOW_FAILURE` | live + test |
| `warnError` | UNSTABLE | BLOCKED `FAILURE_MASKED_BY_ALLOW_FAILURE` | live + test |
| scripted `try/catch` around the scan | stage SUCCESS, step node failed | BLOCKED (caught) | live + test |
| `retry(2)`, second try passes | step failed, same step then succeeded | VERIFIED | live + test |
| stage skipped by `when` | NOT_EXECUTED | BLOCKED `JOB_NOT_SUCCESS` | live + test |
| stage fails, build fails | FAILURE | BLOCKED `JOB_NOT_SUCCESS` | live + test |
| `parallel`: failed `sast-go`, healthy `sast-python` | build SUCCESS | BLOCKED / VERIFIED per branch | live + test |
| `matrix`: `go` instance failed | build SUCCESS | BLOCKED (`job_name: sast` covers every instance) | live + test |
| no Pipeline Graph View plugin | | falls back to Stage View | test |
| step nodes unreadable | | INDETERMINATE | test |

## Azure DevOps and Bitbucket (real API responses)

| Scenario | Decision | Source |
|---|---|---|
| Azure: tasks failed under `continueOnError` (dnceng-public build 1650345) | BLOCKED `FAILURE_MASKED_BY_ALLOW_FAILURE` | test |
| Azure: report artifact published by another job | BLOCKED `REPORT_MISSING` | test |
| Azure: artifact from a re-run job's failed first attempt (azure-sdk 6975296) | not accepted | test |
| Azure: Pipeline Artifact redirected to artifacts.visualstudio.com | INDETERMINATE, token not sent | test |
| Bitbucket: Security Scan step + git-secrets Code Insights report | VERIFIED | test |
| Bitbucket: two reports with one title on a commit (re-run) | newest used | test |
| Bitbucket: failed step in a successful pipeline (`on-fail: ignore`) | BLOCKED `FAILURE_MASKED_BY_ALLOW_FAILURE` | test |

## Scale (measured in the development workspace)

| Input | Time | Peak memory |
|---|---|---|
| Pipeline with 3,000 jobs | 0.06 s (engine) | |
| 52 MB Trivy report | 0.42 s | ~300 MB |
| 59 MB SARIF report | 0.46 s | ~410 MB |

The two large reports were read as local files. Artifact downloads are capped at 50 MB while
streaming (`connectors/http.py`), so a pipeline can't make ScanProof parse anything much bigger.

## Bugs these scenarios found

Run against the code before this change, 21 of these 29 tests fail. The underlying bugs:

1. Jobs in child / multi-project pipelines were invisible, so their requirement reported "job
   absent" (or passed on a same-named parent job).
2. `parallel:` / matrix jobs never matched `job_name`, and a missing instance went unnoticed.
3. A missing report from a job still running was FAIL (BLOCKED) instead of UNKNOWN.
4. A pipeline where no requirement applied was VERIFIED: **fail-open**, now INDETERMINATE.
5. Only the first page of GitHub annotations was read: **fail-open** in principle (see note).
6. A connection dropping mid-download crashed instead of being retried.
