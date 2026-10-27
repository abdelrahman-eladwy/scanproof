# ScanProof

> **Status: v0.1, pre-alpha.** Policy and report formats may still change in minor versions
> before 1.0 (see [CHANGELOG](CHANGELOG.md)). See it work: **[demo](docs/demo.md)**.

**Security Scan Assurance Engine.** ScanProof verifies that the security scans your release
depends on actually ran, produced valid evidence, and covered what you are about to ship.

Works with **GitLab CI**, **GitHub Actions**, **Azure DevOps**, **Jenkins** and **Bitbucket
Pipelines** ([GitLab](docs/platforms/gitlab.md), [GitHub](docs/platforms/github.md),
[Azure DevOps](docs/platforms/azure-devops.md), [Jenkins](docs/platforms/jenkins.md),
[Bitbucket](docs/platforms/bitbucket.md)).

It answers a question most pipelines can't: *"Did SAST and container scanning really run
against this commit and this image — or did a job get skipped, fail with `allow_failure`,
or upload an empty report?"*

ScanProof does **not** decide whether your application is secure. A scan can run perfectly
and still find critical vulnerabilities. ScanProof checks the *scan*, not the *code*.

## Why not just use…

| Option | Gap ScanProof fills |
|---|---|
| GitLab scan execution / pipeline execution policies | Enforce that scans or jobs *run* (Ultimate tier). Their docs don't describe checking that the *report* is valid, covers the code, or is bound to the shipped image digest. ScanProof complements them, and on Free/Premium it is the check you have. ([GitLab docs](https://docs.gitlab.com/user/application_security/policies/)) |
| GitHub required status checks | Prove a job *concluded success*. A scan step that failed under `continue-on-error`, or a scan job skipped by `if:`, still lets the release through. ScanProof detects both (verified on live runs). |
| Checking job status in a script | `success` + `allow_failure` + retries + missing jobs + empty reports = many silent false passes. |
| `cosign verify-attestation` / `gh attestation verify` | Check one signature on one artifact. ScanProof checks that the signed attestation is for *this* report or image, from the pinned workflow, at this commit and in this run, alongside the job and report checks, in one policy. Without signatures it still gives operational assurance. |

## Quick start

```bash
git clone https://github.com/abdelrahman-eladwy/scanproof && cd scanproof
pip install -e ".[dev]"                           # PyPI package arrives with v0.1.0
export GITLAB_TOKEN=glpat-...                     # Developer role + read_api scope (read-only)
export RELEASE_IMAGE_DIGEST=sha256:...            # the image you are about to ship

scanproof validate -P examples/policies/scanproof.yaml
scanproof verify   -P examples/policies/scanproof.yaml --pipeline 1042 -o report.json
```

```
[PASS] SAST-001  semgrep @ semgrep-sast (job 8821)  findings=6
[FAIL] CONTAINER-001  trivy @ trivy-image (job 8830)  findings=2
         FAIL: IMAGE_DIGEST_MISMATCH: Scanned alpine:3.20 (...), expected sha256:a0f5...
Decision: BLOCKED  (1 failed, 0 unknown)  exit 1
```

Supported reports:

| `tool:` | Format | Typical producers |
|---|---|---|
| `semgrep`, `trivy` | native JSON | Semgrep, Trivy |
| `gitlab-sast`, `gitlab-container-scanning` | GitLab security report | GitLab's own CI templates |
| `gitlab-dependency-scanning`, `gitlab-secret-detection` | GitLab security report | GitLab's own CI templates |
| `checkov` | native JSON | Checkov (IaC) |
| `fortify` *(experimental)* | FPR / FVDL | Fortify Static Code Analyzer |
| `sonatype-iq` *(experimental)* | IQ raw application report | Sonatype Lifecycle / IQ Server |
| `sarif` | SARIF 2.1.0 | CodeQL, Semgrep, Trivy, gitleaks, Checkov, Snyk, ... (pin the engine with `expected_scanner`) |
| `cyclonedx` | CycloneDX JSON SBOM | Trivy, Syft, cdxgen, ... |

Tested versions: [docs/compatibility.md](docs/compatibility.md). Which checks each format can
actually prove (SAST, dependency, secrets, IaC, container, SBOM): [docs/scan-types.md](docs/scan-types.md).

Every check returns PASS / FAIL / UNKNOWN / NOT_APPLICABLE with a stable code
(`REQUIRED_JOB_ABSENT`, `FAILURE_MASKED_BY_ALLOW_FAILURE`, `REPORT_MISSING`, `COMMIT_MISMATCH`,
`IMAGE_DIGEST_MISMATCH`, `EVIDENCE_UNAVAILABLE`, ...). Findings are reported, never judged.

On GitHub Actions use `provider: github` in the policy and a `GITHUB_TOKEN` with `actions: read` and
`checks: read` (see [docs/platforms/github.md](docs/platforms/github.md)).

Lower-level commands:

```bash
scanproof inspect -p my-group/my-app --pipeline 1042   # pipeline inventory, no policy
```

Normalize a scanner report into ScanProof evidence (local file, or straight from a CI job; on
GitHub add `--provider github --artifact <name>`):

```bash
scanproof evidence -t semgrep -f semgrep.json
scanproof evidence -t trivy -p my-group/my-app --pipeline 1042 --job trivy-image --report trivy.json
```

Self-hosted GitLab: `--gitlab-url https://gitlab.internal` and, for a private CA,
`--ca-bundle /path/to/ca.pem`. TLS verification cannot be turned off.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | VERIFIED (or `inspect` / `evidence` completed) |
| 1 | BLOCKED: a required control failed |
| 2 | **INDETERMINATE**: evidence could not be obtained (auth, network, unfinished jobs) |
| 3 | Usage error or invalid policy |

A release gate should block on anything non-zero.

`evidence` and `inspect` only describe; they exit 0 even when a report is invalid (the output says
`INVALID`). Use `verify` with a policy to gate.

If no requirement applies to the pipeline (for example every requirement has `applies_to.refs`
and this is a merge-request pipeline), the decision is INDETERMINATE: nothing was verified. Set
`enforcement: {on_nothing_applicable: allow}` to make that VERIFIED with a warning instead.

## Using it in CI

Tested scenarios (child/parallel/matrix pipelines, re-runs, faults, scale) and their results:
[docs/scenarios.md](docs/scenarios.md).

- **GitHub Actions**: [docs/platforms/github.md](docs/platforms/github.md). On GitHub a step that fails under
  `continue-on-error` is reported as *success* by the API; ScanProof still catches it.
- **GitLab CI**: see [docs/platforms/gitlab.md](docs/platforms/gitlab.md) for a copy-paste release gate
([`examples/gitlab-ci/scanproof-gate.gitlab-ci.yml`](examples/gitlab-ci/scanproof-gate.gitlab-ci.yml)),
binding Trivy to the image digest you ship, and where to run the gate so it is hard to bypass.

## Security model

v0.1 provides **operational assurance**: it detects missing, failed, skipped, stale or
malformed scan evidence. On its own it is **not** tamper-proof: someone who can edit the
pipeline can forge a report. Add an `attestation:` block and the report (or image) must also carry
a Sigstore-signed attestation from a pinned workflow, at this commit, in this run
([docs/attestations.md](docs/attestations.md)). Either way, run ScanProof from a protected context
(protected deploy job or a separate audit project) and keep policy files under code-owner
protection. See [`docs/security.md`](docs/security.md).

## Documentation

Full index: **[docs/](docs/README.md)**. Example policies: [examples/](examples/README.md).
Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).
Live end-to-end tests against real CI platforms: [scanproof-e2e](https://github.com/abdelrahman-eladwy/scanproof-e2e).

## Project status

ScanProof is pre-alpha. Current readiness work follows the
[production-readiness program](docs/development/production-readiness.md); active work is tracked in
[GitHub Issues](https://github.com/abdelrahman-eladwy/scanproof/issues). Historical M1–M4
milestone records are in [docs/development/milestones/](docs/development/milestones/).

## License

Apache 2.0
