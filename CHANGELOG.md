# Changelog

All notable changes to ScanProof. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/) (pre-1.0: minor versions may break).

## [Unreleased]

### Added
- `assurance.profile: production` ([#52](https://github.com/abdelrahman-eladwy/scanproof/issues/52)):
  settings that let a weaker pipeline reach VERIFIED are load errors (exit 3), all listed at
  once with a stable code (`JOB_SUCCESS_DISABLED`, `WAIVER_UNBOUNDED`,
  `SIGNER_REPOSITORY_UNPINNED`, ...), and `enforcement.max_waiver_days` may not exceed 90. See
  [docs/advanced-policy.md](docs/advanced-policy.md#production-profile-reject-assurance-weakening-settings).
- `scanproof validate --explain`: shows the policy's minimum assurance level and lists every
  assurance-weakening setting, which ones `production` would reject, and platform limitations
  that no setting removes.

### Compatibility
- The default profile, `compatible`, accepts every policy that loaded before. No evaluation
  changes for any profile.

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
