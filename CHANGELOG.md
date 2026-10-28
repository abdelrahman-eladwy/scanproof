# Changelog

All notable changes to ScanProof. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/) (pre-1.0: minor versions may break).

## [Unreleased]

### Added
- Versioned JSON Schemas for every input and output format in `schemas/`
  ([#47](https://github.com/abdelrahman-eladwy/scanproof/issues/47)), single-sourced from the
  models, drift-checked in CI and validated against real outputs. Rules in
  [docs/compatibility.md](docs/compatibility.md#report-and-policy-schemas).
- `assurance.profile: production` ([#52](https://github.com/abdelrahman-eladwy/scanproof/issues/52)):
  settings that let a weaker pipeline reach VERIFIED are load errors (exit 3), all listed at
  once with a stable code (`JOB_SUCCESS_DISABLED`, `WAIVER_UNBOUNDED`,
  `SIGNER_REPOSITORY_UNPINNED`, ...), and `enforcement.max_waiver_days` may not exceed 90. See
  [docs/advanced-policy.md](docs/advanced-policy.md#production-profile-reject-assurance-weakening-settings).
- `scanproof validate --explain`: shows the policy's minimum assurance level and lists every
  assurance-weakening setting, which ones `production` would reject, and platform limitations
  that no setting removes.
- `instances` on a requirement ([#60](https://github.com/abdelrahman-eladwy/scanproof/issues/60)):
  the matrix legs that must run, by label (`instances: [py, js]` for GitLab `sast: [py]` or
  GitHub `sast (py)` legs). A declared leg with no job is a FAIL, `REQUIRED_INSTANCE_ABSENT`.
  See [docs/advanced-policy.md](docs/advanced-policy.md#matrix-legs-declare-the-instances-that-must-run).
- `copies` on a requirement ([#65](https://github.com/abdelrahman-eladwy/scanproof/issues/65)): the prefixed copies that must run, by path
  (`copies: [svc-a, svc-b]` for GitLab `svc-a > sast`, `[api, web]` for GitHub `api / sast`,
  Jenkins stage paths; `""` for the unprefixed job). A declared copy with no job is a FAIL,
  `REQUIRED_COPY_ABSENT`. See
  [docs/advanced-policy.md](docs/advanced-policy.md#prefixed-copies-declare-the-copies-that-must-run).

### Fixed
- `verify-release`: a component `pipeline` must be a positive decimal id or a `${ENV_VAR}`
  resolving to one. YAML `pipeline: yes`/`on`/`true` used to become pipeline **1** (bool is
  an int), silently verifying the wrong pipeline; zero, negative, float, `1_000` and `+5`
  were also accepted. All are now load errors (exit 3).
- `verify -o` on an unreadable pipeline now writes a typed report with `scanproof_version`
  and `generated_at` (fields added; existing fields unchanged).
- **P0 GitHub gate-only rerun false VERIFIED** ([#90](https://github.com/abdelrahman-eladwy/scanproof/issues/90)):
  GitHub may present synthetic current-attempt job IDs for earlier scans when only the
  verification job is rerun, without the original step-failure annotations. ScanProof
  could treat masked `continue-on-error` failures as clean. Successful jobs that did
  not start in the current attempt, or whose attempt timing is unprovable, now produce
  `STEP_MASKING_UNKNOWN` (INDETERMINATE) instead of VERIFIED; fresh jobs still verify.
- **P0 false VERIFIED for oversized GitLab parallel totals** ([#88](https://github.com/abdelrahman-eladwy/scanproof/issues/88)):
  `sast 1/1001` with one passing report could satisfy a required scan even though 1,000
  advertised legs were absent: a cap on missing-name enumeration silently disabled the
  missing-leg check. Completeness is now checked for every positive total, with one bounded
  diagnostic for groups above 1,000. Invalid indices, contradictory totals and oversized
  decimal values fail closed, while truly complete large groups can still verify.
- **GitLab root trigger list 404** ([#44](https://github.com/abdelrahman-eladwy/scanproof/issues/44)):
  a 404 on the root pipeline's bridges was read as "no child pipelines", so a failing child copy
  of a passing root job went unseen (VERIFIED under `production`). It is now unreadable like any
  other trigger-list error: `COPIES_UNBOUNDED` under `production`, a warning under `compatible`,
  and declared child copies stay UNKNOWN. Root jobs are still proven, as their list was read.
- **Zip bombs by entry count** ([#44](https://github.com/abdelrahman-eladwy/scanproof/issues/44)):
  an artifact or Fortify FPR whose central directory lists more than 50,000 entries or is larger
  than 8 MiB is refused (`LIMIT_EXCEEDED`, UNKNOWN) before `zipfile` builds an object per entry;
  a 33 MiB archive of 400,000 empty members took 18 s and 219 MiB just to open.
- **Hostile providers** ([#44](https://github.com/abdelrahman-eladwy/scanproof/issues/44)): a
  pagination loop is detected at once (it used to cost up to 100 requests); a non-numeric GitLab
  `X-Next-Page` is a connector error instead of a crash; API pages are size-capped like
  downloads; each response body must arrive within 300 s and a connector's requests within
  30 min, so a slowly dripping server can no longer hang `verify`. All end as UNKNOWN (exit 2).
- **Attestations:** a bundle signed after its Fulcio CA, Rekor key or CT log key was retired
  (the trust root's `validFor` window had ended) verified, because sigstore-python 4.x checks
  those windows against the current time only. ScanProof now requires every recorded signing
  time to fall inside them (`ATTESTATION_INVALID`). A GitHub run whose URL is unknown no longer
  counts as the signing run on run id alone (`ATTESTATION_RUN_UNKNOWN`)
  ([#44](https://github.com/abdelrahman-eladwy/scanproof/issues/44)).
- `--anonymous` help, the missing-token error and the anonymous GitLab 429 message now state that
  gitlab.com and api.github.com allow 60 unauthenticated API requests per hour per IP, and
  suggest a `read_api` token ([#74](https://github.com/abdelrahman-eladwy/scanproof/issues/74)).
- **False VERIFIED:** a job named exactly like a requirement's `job_name` hid that name's
  matrix, parallel, downstream and reusable-workflow instances, so a passing `sast` could stand
  in for a failing `sast (py)`, `sast 1/2` or `trigger > sast`
  ([#59](https://github.com/abdelrahman-eladwy/scanproof/issues/59)). Now every job the name
  covers is evaluated and all must pass.
- **False VERIFIED:** a leg removed from a GitLab `parallel: matrix:` or GitHub
  `strategy.matrix` went unnoticed, because matrix names carry no total
  ([#60](https://github.com/abdelrahman-eladwy/scanproof/issues/60)). Declare `instances` to
  detect it; `assurance.profile: production` requires the declaration when matrix legs are
  matched (`INSTANCES_UNDECLARED`, UNKNOWN).
- **False VERIFIED:** removing one of several copies told apart only by a prefix (a GitLab
  downstream pipeline, a GitHub reusable-workflow caller, a Jenkins matrix stage) went
  unnoticed, also under `assurance.profile: production` ([#65](https://github.com/abdelrahman-eladwy/scanproof/issues/65)). Declare `copies` to detect it;
  `production` requires the declaration when a prefixed copy is matched (`COPIES_UNDECLARED`,
  UNKNOWN), and rejects a waiver on `copies_declared` (`WAIVER_HIDES_UNDECLARED_COPIES`).

- **Overclaimed VERIFIED under `production`:** a job found in the pipeline was VERIFIED even
  when a downstream pipeline that could not be read (or had not started) might hold another
  copy of it, which must pass too ([#71](https://github.com/abdelrahman-eladwy/scanproof/issues/71)). It is now UNKNOWN (`COPIES_UNBOUNDED`) unless the
  requirement declares `copies` (`[""]` for the pipeline's own job only); a waiver on
  `copies_bounded` is rejected (`WAIVER_HIDES_UNBOUNDED_COPIES`). `compatible`: a warning.
- **Incorrect BLOCKED:** a GitLab trigger that had not started its downstream pipeline yet
  (created, pending, waiting, running, or an unrecognized status) made every job and declared
  copy in that pipeline `REQUIRED_JOB_ABSENT` / `REQUIRED_COPY_ABSENT`
  ([#68](https://github.com/abdelrahman-eladwy/scanproof/issues/68)). It is now an unreadable
  downstream, so absence is INDETERMINATE (`JOB_MAYBE_IN_UNREADABLE_PIPELINE`). Failed,
  canceled, skipped and unplayed manual triggers are still absent. Documented in
  [docs/advanced-policy.md](docs/advanced-policy.md#missing-or-unreadable-when-absence-is-proven).

### Compatibility
- The default profile, `compatible`, accepts every policy that loaded before. No evaluation
  changes under `compatible`. Under `production`, a requirement whose job runs as matrix legs
  and declares no `instances` is now UNKNOWN (exit 2) instead of evaluating only the legs that
  ran; under `compatible` it gets a warning.
- **Breaking under `production` only:** a requirement whose bare `job_name` matches a
  downstream (`svc-a > sast`), reusable-workflow (`api / sast`) or nested Jenkins stage copy
  and declares no `copies` is now UNKNOWN (exit 2). Add `copies`, or pin each copy with a
  qualified `job_name`. Under `compatible` it gets a warning; decisions are unchanged.
- **Breaking under `production` only:** a requirement with an unqualified `job_name` and no
  `copies` is UNKNOWN (exit 2) when a GitLab downstream pipeline can't be read or hasn't
  started. Add `copies` (`[""]` if only the pipeline's own job is required).
- Requirements without `instances` behave as before. `find_jobs` keeps its signature;
  `match_jobs` is the richer form.
- A pipeline that has both an exact-name job and same-named instances now needs every one of
  them to pass, where before only the exact job counted. If such a job really is unrelated,
  rename it. Pipelines with only an exact job or only instances are unchanged.

## [0.1.0] - unreleased

First release. ScanProof verifies security-scan **evidence** in CI: that required scans ran,
succeeded, produced a valid report for the right commit and image, and covered the code.

### Platforms
- **GitLab CI**: pipelines, retried jobs, `allow_failure`, manual jobs, parent/child and
  multi-project pipelines (via bridges; downstream evidence is attributed to the project and
  pipeline it came from), `parallel:` and `parallel: matrix:` jobs. Self-managed instances with
  `--gitlab-url` and `--ca-bundle`; `--anonymous` for public projects.
- **GitHub Actions**: workflow runs and re-run attempts, matrix and reusable-workflow jobs,
  masked failures from step- and job-level `continue-on-error` (via check-run annotations),
  run artifacts checked against GitHub's recorded sha256 digest.
- **Azure DevOps, Jenkins and Bitbucket Pipelines** (`--provider azure-devops | jenkins |
  bitbucket`, `--url`, `--user-env`, `--auth-scheme`). Each sees through its own masking: Azure
  `continueOnError` (`succeededWithIssues`), Jenkins `catchError` / `warnError` / swallowed
  `try/catch` step failures (but not `retry`), Bitbucket `on-fail: ignore`. Azure reports must
  come from an artifact the required job published itself. Bitbucket evidence is Code Insights
  reports (tool `bitbucket-code-insights`).

### Scanners and formats
- Semgrep (JSON), Trivy (image and filesystem JSON), SARIF 2.1 (any producer), CycloneDX SBOMs,
  Checkov, GitLab security reports (SAST, container, dependency, secret detection).
- Gitleaks (native JSON), Grype, OSV-Scanner, Snyk (open source and container), Kubescape, and
  the DAST scanners OWASP ZAP and Nuclei.
- Experimental: Fortify FPR, Sonatype IQ.

### Policy
- YAML policies (`scanproof.dev/v1alpha1`) with unknown keys rejected.
- Checks: `job_success`, `same_commit`, `report_required`, `scanner_errors_allowed`,
  `ignore_scanner_warnings`, `minimum_scanned_files`, `required_paths`, `image_digest_must_match`,
  `expected_scanner`, `minimum_components`, `minimum_resources`; `applies_to.refs`.
- DAST checks: `target_url_must_match` (the scan hit the URL being released: same origin, path
  at or below it) and `minimum_endpoints` (ZAP's endpoint count). Scan type `DAST`.
- `max_age_hours` (scan freshness from the platform's job finish time; implausibly future
  timestamps are UNKNOWN) and `same_target_as` (two requirements' scans must be about the same
  image digest or DAST origin).
- **Waivers** with reason, approver and expiry (`waivers:`, `enforcement.max_waiver_days`): a
  matching failed or unknown check becomes `WAIVED` until it expires.
- **Opt-in reported-scope assurance** (`assurance.minimum_level: reported_scope`): the scanner's
  own report must claim a nonempty scan scope. An explicitly empty scope fails, undeterminable
  scope is UNKNOWN, and settings that would fail open (`on_unknown: warn`, ...) are rejected.
- **Signed evidence.** `attestation:` on a requirement demands a Sigstore-signed in-toto
  attestation for the report or the image, verified with sigstore-python (optional extra
  `scanproof[attestations]`), then checked for subject digest, predicate type, signer (issuer
  plus repository and/or Build Signer URI regex), same commit, same run and, on GitHub, the
  current run attempt. Sources: a bundle in the job or run artifacts, or the GitHub
  attestations API. SLSA provenance, cosign `vuln` predicates and plain message signatures
  (`sigstore sign`, `cosign sign-blob`) are supported.
- Outcomes PASS / FAIL / UNKNOWN / NOT_APPLICABLE / WAIVED; unknown never counts as pass.
  `enforcement.on_failure`, `on_unknown`, `on_nothing_applicable`.

### CLI
- `inspect`, `evidence`, `validate`, `verify`; console report on stderr, JSON on stdout or `-o`.
- `verify-release -R release.yaml`: one decision over several pipelines on any platforms
  (`ReleaseAssurance` files).
- `attestation -b BUNDLE [-f FILE]` prints what a bundle proves; `--sigstore-trusted-root`
  (e.g. GitHub's instance for private repositories) and `--sigstore-offline`.
- Exit codes: 0 verified, 1 blocked, 2 indeterminate, 3 usage or policy error.

### Security
- Tokens (and usernames, for HTTP Basic: Jenkins API tokens, Azure DevOps PATs, Bitbucket API
  tokens) only from environment variables, sent only to the configured API origin, never logged.
- TLS always verified; manual redirect handling (no HTTPS to HTTP); streamed, size-capped
  downloads; retries with `Retry-After`; untrusted XML parsed with defusedxml.
- Fail-closed path handling: `required_paths` match whole path segments; absolute, empty, root
  or escaping paths are rejected; a pipeline with no known ref is UNKNOWN, not "not applicable".
- Scanner reports with unpaired Unicode surrogates are rejected rather than half-parsed.
- Release artifacts (PyPI package, GHCR image) carry SLSA build-provenance attestations.

### Tested against
- Real scanner output and real gitlab.com, GitHub, Azure DevOps, Bitbucket and Jenkins API
  responses; every adapter fuzzed with corrupted real reports; an adversarial false-VERIFIED
  decision matrix; lowest supported dependency versions on Python 3.12.
- Live runs against real platforms in
  [scanproof-e2e](https://github.com/abdelrahman-eladwy/scanproof-e2e), including ScanProof
  verifying its own GitHub runs and attestations; scenarios in `docs/scenarios.md`, demo in
  `docs/demo.md`.

[Unreleased]: https://github.com/abdelrahman-eladwy/scanproof/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/abdelrahman-eladwy/scanproof/releases/tag/v0.1.0
