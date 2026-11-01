# Operator runbook: ScanProof release-gate decisions

**Scope:** ScanProof 0.1 pre-alpha; five CI connectors. This runbook addresses gate diagnosis,
not CI-provider branch protection. A ScanProof exit code alone cannot prevent a mutable
workflow from being removed. See [protected release gates](../protected-release-gates.md).

## Gate response contract

| Exit | Meaning | Deployment action |
|---|---|---|
| 0 — VERIFIED | The configured policy's applicable checks passed or were visibly waived | Continue only after independent CI deployment protection also authorizes the run |
| 1 — BLOCKED | At least one required check failed | Deny deployment; correct the scan/job/commit mismatch or obtain approved remediation |
| 2 — INDETERMINATE | ScanProof cannot establish the evidence or scope | Deny deployment; restore visibility or retry; never turn unknown into pass |
| 3 — configuration / usage | Invalid policy, arguments, release configuration, or unsupported setting | Deny deployment; repair and independently review the policy |

Do **not** use `inspect` or `evidence` exit 0 as a release pass. Only `verify` and
`verify-release` evaluate a release policy. In release orchestration, each policy must
use `assurance.profile: production`.

## First 5 minutes

1. Freeze the pipeline ID, project, provider, commit SHA, policy revision and image digest
   intended for deployment. Preserve the ScanProof JSON report and sanitized CI logs.
2. Run `scanproof inspect -p PROJECT --pipeline PIPELINE_ID` using the **same** provider
   credentials and URL as the gate. Confirm the expected job, latest attempt, commit binding,
   artifacts, child pipeline and matrix copies.
3. Run `scanproof validate --explain -P policy.yaml`. Fix any production-profile opt-in
   violations; do not switch to `compatible` to make a release green.
4. Re-run `scanproof verify -P policy.yaml -p PROJECT --pipeline PIPELINE_ID -o report.json`
   from a protected execution context. Check `requirements[].checks[]` for `code`,
   `outcome`, `message`, and `waived_unknown`, not only the top-level decision.
5. If a report is missing, use `scanproof evidence -t TOOL -p PROJECT --pipeline PIPELINE_ID
   --job JOB --report PATH` to investigate only. Treat the tool's diagnostic output
   as a description, not release authorization.

## Error/decision routing

| Symptom / code | Investigation | Safe resolution |
|---|---|---|
| `REQUIRED_JOB_ABSENT`, `JOB_NOT_SUCCESS`, `JOB_NOT_FINISHED` | Correct job name, latest attempt and full matrix/copy count; inspect downstream triggers | Restore or complete the required job. Use bounded settle retries only for legitimately unfinished jobs |
| `REPORT_MISSING`, `EVIDENCE_UNAVAILABLE` | Check report path, retention/expiration, artifact type, child project origin, permissions | Publish a new scanner report; do not reuse an unrelated job's artifact |
| `COMMIT_MISMATCH` or target/digest mismatch | Confirm pipeline SHA, selected deployment artifact and immutable `@sha256:` reference | Rebuild/re-scan and bind evidence to the exact intended commit/digest |
| `FAILURE_MASKED_BY_ALLOW_FAILURE` | Inspect `allow_failure`, `continue-on-error`, rerun attempts and annotations | Remove masking or rerun scanner as a required failure-propagating job |
| `AUTH` (401/403) | Token scope, project visibility, expired token and cross-project child access | Fix least-privileged permissions; never print tokens or disable TLS |
| `RATE_LIMITED` (429) | GitLab anonymous quota, provider retry headers, excessive polling | Prefer scoped authenticated access and bounded backoff; keep gate denied until evidence available |
| `NETWORK`, `SERVER` (5xx), timeout | Provider incident, DNS, private CA, request/run budget | Retry with an explicit limit; escalate persistent outage without bypassing gate |
| `INVALID_RESPONSE`, `INTEGRITY`, `LIMIT_EXCEEDED` | Malformed or oversized archive/JSON, unexpected pagination, content hash or parser failure | Investigate source; do not raise limits casually or accept unparseable evidence |
| Attestation signer, run, commit or trust-root mismatch | Bundle subject digest, pinned signer, trusted root and run attempt | Reissue evidence under approved signer; never waive cryptographic identity without security approval |

An absent resource is **not** the same as an unreadable resource. A provider that cannot
be queried yields INDETERMINATE. Capture a redacted reproducer if the code reports
`REPORT_MISSING` when access is actually unknown.

## Triage, escalation and recovery

- **P0**: unexpected VERIFIED with missing/failed/foreign evidence, bypassable protected gate,
  or credential exposure. Stop promotions, isolate affected deployments and open a
  **private security advisory**; do not publish active exploit details in an issue.
- **P1**: incorrect BLOCKED/INDETERMINATE, availability failure, or unsupported authentic
  reports. Stop affected pilot; record the provider HTTP response and minimal fixture.
- **P2**: documentation, presentation or measured performance issue without gate impact.

Do not "fix" an outage by replacing `on_unknown: block` with `warn`, ignoring scanner
warnings, removing evidence checks, disabling signature validation, or accepting a stale
green pipeline. Review any waiver's scope, approver, ticket and expiration; production
profile rejects waivers that conceal fundamental required controls.

If deployment was incorrectly authorized, immediately disable the deployment credential
path, investigate which releases passed, and roll back through independently controlled
release infrastructure. Preserve signed attestations and SHA-256 hashes of captured files
without exposing secrets. Escalate security incidents using [SECURITY.md](../../SECURITY.md).

## Evidence required to close an incident

Record the affected version/commit, policy and intended SHA/digest, provider name and
topology, sanitized API status and response class, original and corrected decision/exit,
regression-test link, merged PR, all required CI results and **post-merge** main run. For
platform gate incidents, attach a protected deployment denial and successful controlled
positive path as separate live evidence. The application remains NO-GO until the
[production-readiness exit gates](../development/production-readiness.md) are satisfied.

**Limitations:** The verification report currently lacks the complete inspected-job input,
so offline re-evaluation from `report.json` is not supported. Re-run against the provider
to obtain fresh evidence. Scanner-reported scope is not independent proof of scanner
completeness.
