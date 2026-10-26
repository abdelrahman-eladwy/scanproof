# ScanProof

> **Status: experimental (pre-alpha).** Interfaces and output formats will change before v0.1.

**Security Scan Assurance Engine.** ScanProof verifies that the security scans your release
depends on actually ran, produced valid evidence, and covered what you are about to ship.

Works with **GitLab CI** and **GitHub Actions**.

It answers a question most pipelines can't: *"Did SAST and container scanning really run
against this commit and this image — or did a job get skipped, fail with `allow_failure`,
or upload an empty report?"*

ScanProof does **not** decide whether your application is secure. A scan can run perfectly
and still find critical vulnerabilities. ScanProof checks the *scan*, not the *code*.

## Why not just use…

| Option | Gap ScanProof fills |
|---|---|
| GitLab scan execution / pipeline execution policies | Enforce that scans or jobs *run* (Ultimate tier). Their docs don't describe checking that the *report* is valid, covers the code, or is bound to the shipped image digest. ScanProof complements them, and on Free/Premium it is the check you have. ([GitLab docs](https://docs.gitlab.com/user/application_security/policies/)) |
| Checking job status in a script | `success` + `allow_failure` + retries + missing jobs + empty reports = many silent false passes. |
| Sigstore / in-toto attestations | The right long-term answer (ScanProof's v0.2+ direction), but most teams don't have it yet. ScanProof gives assurance today and a path there. |

## Quick start

```bash
pip install -e ".[dev]"
export GITLAB_TOKEN=glpat-...                     # read_api scope, read-only
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
| `sarif` | SARIF 2.1.0 | CodeQL, Semgrep, Trivy, gitleaks, Checkov, Snyk, ... (pin the engine with `expected_scanner`) |
| `cyclonedx` | CycloneDX JSON SBOM | Trivy, Syft, cdxgen, ... |

Tested versions: [docs/compatibility.md](docs/compatibility.md). Which checks each format can
actually prove (SAST, dependency, secrets, IaC, container, SBOM): [docs/scan-types.md](docs/scan-types.md).

Every check returns PASS / FAIL / UNKNOWN / NOT_APPLICABLE with a stable code
(`REQUIRED_JOB_ABSENT`, `FAILURE_MASKED_BY_ALLOW_FAILURE`, `REPORT_MISSING`, `COMMIT_MISMATCH`,
`IMAGE_DIGEST_MISMATCH`, `EVIDENCE_UNAVAILABLE`, ...). Findings are reported, never judged.

Lower-level commands:

```bash
scanproof inspect -p my-group/my-app --pipeline 1042   # pipeline inventory, no policy
```

Normalize a scanner report into ScanProof evidence (local file, or straight from a GitLab job):

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

## Roadmap to v0.1

- [x] **M1 — GitLab Pipeline Inspector**
- [x] **M2 — Scanner adapters:** Semgrep (scan scope, errors) and Trivy (image digest binding)
- [x] **M3 — Policy engine:** YAML policies, PASS / FAIL / UNKNOWN / NOT_APPLICABLE, `verify` command
- [ ] **M4 — Hardening & release:** pinned CI, release workflow with provenance, docs (done); demo project and first PyPI release (pending)

See [`docs/issues/`](docs/issues/) for detailed acceptance criteria.

## Using it in CI

- **GitHub Actions**: [docs/usage-github.md](docs/usage-github.md). On GitHub a step that fails under
  `continue-on-error` is reported as *success* by the API; ScanProof still catches it.
- **GitLab CI**: see [docs/usage-gitlab.md](docs/usage-gitlab.md) for a copy-paste release gate
([`examples/gitlab-ci/scanproof-gate.gitlab-ci.yml`](examples/gitlab-ci/scanproof-gate.gitlab-ci.yml)),
binding Trivy to the image digest you ship, and where to run the gate so it is hard to bypass.

## Security model

v0.1 provides **operational assurance**: it detects missing, failed, skipped, stale or
malformed scan evidence. It is **not** tamper-proof: someone who can edit the pipeline can
forge a report. Run ScanProof from a protected context (protected deploy job or a separate
audit project) and keep policy files under code-owner protection. Cryptographic evidence
(attestations, SLSA provenance) is the v0.2+ direction. See [`docs/security.md`](docs/security.md).

## License

Apache 2.0
