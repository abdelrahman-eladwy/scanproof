# ScanProof

> **Status: experimental (pre-alpha).** Interfaces and output formats will change before v0.1.

**Security Scan Assurance Engine.** ScanProof verifies that the security scans your release
depends on actually ran, produced valid evidence, and covered what you are about to ship.

It answers a question most pipelines can't: *"Did SAST and container scanning really run
against this commit and this image — or did a job get skipped, fail with `allow_failure`,
or upload an empty report?"*

ScanProof does **not** decide whether your application is secure. A scan can run perfectly
and still find critical vulnerabilities. ScanProof checks the *scan*, not the *code*.

## Why not just use…

| Option | Gap ScanProof fills |
|---|---|
| GitLab Ultimate scan execution / pipeline execution policies | Force scans to *run*; don't verify the *report* is valid, non-empty, and bound to the shipped image. Ultimate-only. |
| Checking job status in a script | `success` + `allow_failure` + retries + missing jobs + empty reports = many silent false passes. |
| Sigstore / in-toto attestations | The right long-term answer (ScanProof's v0.2+ direction), but most teams don't have it yet. ScanProof gives assurance today and a path there. |

## What works today (Milestone 1: Pipeline Inspector)

```bash
pip install -e ".[dev]"
export GITLAB_TOKEN=glpat-...          # read_api scope, read-only
scanproof inspect --project my-group/my-app --pipeline 1042 -o inspection.json
```

Produces a JSON inventory of the pipeline: every job, its effective (latest) attempt, retry
history, `allow_failure`, commit binding, and artifacts — plus warnings for things that
deserve a second look. No policy is applied yet.

Self-hosted GitLab: `--gitlab-url https://gitlab.internal` and, for a private CA,
`--ca-bundle /path/to/ca.pem`. TLS verification cannot be turned off.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed (verification passed, from milestone 3) |
| 1 | Policy failure (milestone 3) |
| 2 | **Indeterminate** — could not obtain evidence (auth, network, not found) |
| 3 | Usage error |

A release gate should block on anything non-zero.

## Roadmap to v0.1

- [x] **M1 — GitLab Pipeline Inspector**
- [ ] **M2 — Scanner adapters:** Semgrep (scan scope, errors) and Trivy (image digest binding)
- [ ] **M3 — Policy engine:** YAML policies, PASS / FAIL / UNKNOWN / NOT_APPLICABLE, `verify` command
- [ ] **M4 — Hardening & release:** Docker image, docs, demo project, PyPI

See [`docs/issues/`](docs/issues/) for detailed acceptance criteria.

## Security model

v0.1 provides **operational assurance**: it detects missing, failed, skipped, stale or
malformed scan evidence. It is **not** tamper-proof: someone who can edit the pipeline can
forge a report. Run ScanProof from a protected context (protected deploy job or a separate
audit project) and keep policy files under code-owner protection. Cryptographic evidence
(attestations, SLSA provenance) is the v0.2+ direction. See [`docs/security.md`](docs/security.md).

## License

Apache 2.0
