# Changelog

All notable changes to ScanProof. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/) (pre-1.0: minor versions may break).

## [Unreleased]

### Added
- **Signed evidence.** `attestation:` on a requirement demands a Sigstore-signed in-toto
  attestation for the report or the image: verified with sigstore-python (optional extra
  `scanproof[attestations]`), then checked for subject digest, predicate type, signer
  (issuer + repository and/or Build Signer URI regex), same commit and same run. Sources: a bundle
  in the job/run artifacts, or the GitHub attestations API. SLSA provenance, cosign `vuln`
  predicates and plain message signatures (`sigstore sign`, `cosign sign-blob`) are supported.
  Tested against real bundles from this repository's own runs, forgeries made from them, and a
  live self-verify run. See `docs/attestations.md`.
- `scanproof attestation -b BUNDLE [-f FILE]` prints what a bundle proves.
- `--sigstore-trusted-root` (e.g. GitHub's instance for private repos) and `--sigstore-offline`.

### Fixed
- Docker smoke test could pass when `docker run` itself failed.

## [0.1.0] - unreleased

First release. ScanProof verifies security-scan **evidence** in CI: that required scans ran,
succeeded, produced a valid report for the right commit and image, and covered the code.

### Platforms
- **GitLab CI**: pipelines, retried jobs, `allow_failure`, manual jobs, parent/child and
  multi-project pipelines (via bridges), `parallel:` and `parallel: matrix:` jobs. Self-managed
  instances with `--gitlab-url` and `--ca-bundle`; `--anonymous` for public projects.
- **GitHub Actions**: workflow runs and re-run attempts, matrix and reusable-workflow jobs,
  masked failures from step- and job-level `continue-on-error` (via check-run annotations),
  run artifacts checked against GitHub's recorded sha256 digest.

### Scanners and formats
- Semgrep (JSON), Trivy (image and filesystem JSON), SARIF 2.1 (any producer), CycloneDX SBOMs,
  Checkov, GitLab security reports (SAST, container, dependency, secret detection).
- Experimental: Fortify FPR, Sonatype IQ.

### Policy
- YAML policies (`scanproof.dev/v1alpha1`) with unknown keys rejected.
- Checks: `job_success`, `same_commit`, `report_required`, `scanner_errors_allowed`,
  `ignore_scanner_warnings`, `minimum_scanned_files`, `required_paths`, `image_digest_must_match`,
  `expected_scanner`, `minimum_components`, `minimum_resources`; `applies_to.refs`.
- Outcomes PASS / FAIL / UNKNOWN / NOT_APPLICABLE; unknown never counts as pass.
  `enforcement.on_failure`, `on_unknown`, `on_nothing_applicable`.

### CLI
- `inspect`, `evidence`, `validate`, `verify`; console report on stderr, JSON on stdout or `-o`.
- Exit codes: 0 verified, 1 blocked, 2 indeterminate, 3 usage or policy error.

### Security
- Tokens only from environment variables, sent only to the configured API origin, never logged.
- TLS always verified; manual redirect handling (no HTTPS to HTTP); streamed, size-capped
  downloads; retries with `Retry-After`; untrusted XML parsed with defusedxml.
- Release artifacts (PyPI package, GHCR image) carry SLSA build-provenance attestations.

### Tested against
- Real scanner output and real gitlab.com / GitHub API responses; live GitHub runs verify
  ScanProof's own workflow; adapters fuzzed; complex scenarios in `docs/scenarios.md`; demo in
  `docs/demo.md`. Lowest supported dependency versions tested on Python 3.12.

[0.1.0]: https://github.com/abdelrahman-eladwy/scanproof/releases/tag/v0.1.0
