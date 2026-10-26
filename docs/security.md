# Security model

## What ScanProof v0.1 claims

**Operational assurance:** given read access to a pipeline, ScanProof reports whether the
required scan jobs exist, finished successfully without `allow_failure` masking, produced
parseable reports with acceptable scope and no scanner errors, and are bound to the pipeline
commit (and, for container scans, the image digest).

## What it does not claim

- That the application is secure.
- That evidence is tamper-proof. Anyone who can edit `.gitlab-ci.yml` or the runner can forge a
  report. Cryptographic binding (attestations, SLSA provenance) is planned for v0.2+.

## Where to run it

Running ScanProof *inside the same pipeline it checks* gives weak guarantees: whoever can remove
the scan job can also remove the ScanProof job. Prefer one of:

1. A **protected deploy job** whose definition comes from a protected/included config the
   application team cannot modify.
2. A **separate audit project** that inspects pipelines with a read-only token
   (scheduled, or triggered before release).

Keep policy files under code-owner protection.

## Handling of credentials and network

| Control | Implementation |
|---|---|
| Least privilege | GitLab: `read_api` (Developer role for security-report artifacts). GitHub: `actions: read` + `checks: read`. ScanProof never writes to the CI platform |
| No token leakage | Env var only; `Authorization: Bearer`; excluded from `repr`, errors, logs |
| Redirects | Followed manually; credentials only to the configured origin; HTTPS->HTTP refused; max 3 |
| TLS | Always verified; private CAs via `--ca-bundle` |
| Resource limits | Artifact downloads streamed and capped (50 MB default); zip members capped while reading (zip-bomb safe); pagination capped and must stay on the API origin |
| Artifact integrity | GitHub: downloaded zip must match the sha256 digest GitHub recorded, otherwise BLOCKED |
| Failure semantics | Any error -> INDETERMINATE (exit 2), never pass |
