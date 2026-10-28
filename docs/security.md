# Security model

## What ScanProof v0.1 claims

**Operational assurance:** given read access to a pipeline, ScanProof reports whether the
required scan jobs exist, finished successfully without `allow_failure` masking, produced
parseable reports with acceptable scope and no scanner errors, and are bound to the pipeline
commit (and, for container scans, the image digest).

## What it does not claim

- That the application is secure.
- That evidence is tamper-proof, **unless the requirement has an `attestation:` block.** Without
  one, anyone who can edit `.gitlab-ci.yml` or the runner can forge a report. With one, the
  report (or image) must carry a Sigstore-signed attestation from a pinned workflow, at the
  pipeline commit, in the verified run; edited, swapped, replayed or foreign-signed evidence
  fails. It still cannot stop someone who can push to the ref the signing workflow runs from.
  See [attestations.md](attestations.md).

## Where to run it

Running ScanProof *inside the same pipeline it checks* gives weak guarantees: whoever can remove
the scan job can also remove the ScanProof job. This holds for both `.gitlab-ci.yml` and GitHub
workflow files. Prefer one of:

1. A **protected deploy job** whose definition comes from a protected/included config the
   application team cannot modify.
2. A **separate audit project** that inspects pipelines with a read-only token
   (scheduled, or triggered before release).

Set `assurance.profile: production` on release-gate policies so that a policy edit weakening
assurance (`job_success: false`, unbounded waivers, an unpinned signer, ...) is rejected
instead of quietly passing review ([production profile](advanced-policy.md#production-profile-reject-assurance-weakening-settings)).
The profile is a review aid, not an access control: whoever can edit the policy can also
remove the profile line. That's why the protection below still matters.

Keep policy files under code-owner protection. See the [protected release gate guide](protected-release-gates.md)
for platform-enforced status checks, CODEOWNERS setup, and adversarial validation steps.
A CODEOWNERS file by itself does not enforce approval.

## Handling of credentials and network

| Control | Implementation |
|---|---|
| Least privilege | GitLab: `read_api` (Developer role for security-report artifacts). GitHub: `actions: read` + `checks: read` (+ `attestations: read` for `source: platform`). Azure DevOps: Build (Read). Jenkins: Job/Read. Bitbucket: pipelines + repository read. ScanProof never writes to the CI platform |
| No token leakage | Env var only (username too, for Basic); `Authorization: Bearer`, or Basic where the platform requires it (Jenkins, Azure DevOps PATs, Bitbucket API tokens); only to the API origin; excluded from `repr`, errors, logs |
| Redirects | Followed manually; credentials only to the configured origin; HTTPS->HTTP refused; max 3 |
| TLS | Always verified; private CAs via `--ca-bundle` |
| Resource limits | Artifact downloads streamed and capped (50 MB default); zip members capped while reading, and archives over 50,000 entries or an 8 MiB central directory refused before opening (zip-bomb safe); pagination capped and must stay on the API origin |
| Artifact integrity | GitHub: downloaded zip must match the sha256 digest GitHub recorded, otherwise BLOCKED |
| Untrusted report content | Adapters never raise: malformed, wrong-typed, deeply nested or absurd input becomes "unparseable". Every adapter is fuzzed in CI with corrupted real reports; XML uses defusedxml |
| Signed evidence | Sigstore verification by sigstore-python (chain, log/timestamp, DSSE); claims read only from a verified certificate; signer must pin repository or workflow; bundles fuzzed in CI; signed blob URLs never stored |
| Failure semantics | Any error -> INDETERMINATE (exit 2), never pass |
