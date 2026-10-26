# M3 — Policy engine and `scanproof verify`

**Goal:** evaluate a YAML policy against inspection + evidence and return a decision.

## Design

- `policy/models.py`: Pydantic models for `examples/policies/scanproof.yaml`
  (`apiVersion: scanproof.dev/v1alpha1`). Unknown keys are an error (`extra="forbid"`), so a typo
  in a check name cannot silently disable it.
- `policy/engine.py`: pure function `evaluate(policy, inspection, evidence_by_req) -> Decision`.
  No I/O. Each check returns `PASS | FAIL | UNKNOWN | NOT_APPLICABLE` with a machine code
  (`REQUIRED_JOB_ABSENT`, `JOB_NOT_SUCCESS`, `FAILURE_MASKED_BY_ALLOW_FAILURE`, `REPORT_MISSING`,
  `REPORT_UNPARSEABLE`, `SCANNER_ERRORS`, `SCOPE_TOO_SMALL`, `COMMIT_MISMATCH`,
  `IMAGE_DIGEST_MISMATCH`, `EVIDENCE_UNAVAILABLE`) and a human message.
- Aggregation: any FAIL -> BLOCKED (exit 1); else any UNKNOWN -> INDETERMINATE (exit 2,
  unless `on_unknown: warn`); else VERIFIED (exit 0).
- `scanproof verify -p .. --pipeline .. --policy scanproof.yaml -o report.json`.

## Acceptance criteria (the acceptance suite from the design doc)

| Scenario | Expected |
|---|---|
| Both scans succeed with valid evidence | VERIFIED, 0 |
| SAST job absent | BLOCKED (`REQUIRED_JOB_ABSENT`), 1 |
| SAST failed with `allow_failure: true` | BLOCKED (`FAILURE_MASKED_BY_ALLOW_FAILURE`), 1 |
| Job succeeded, no report | BLOCKED (`REPORT_MISSING`), 1 |
| Report has scanner errors / is invalid | BLOCKED, 1 |
| API returns 403 | INDETERMINATE (`EVIDENCE_UNAVAILABLE`), 2 |
| Report from another commit | BLOCKED (`COMMIT_MISMATCH`), 1 |
| Trivy scanned a different image | BLOCKED (`IMAGE_DIGEST_MISMATCH`), 1 |
| Findings present, scan complete | VERIFIED (findings are reported, not judged), 0 |
| Retried job: failed then succeeded | VERIFIED, retry recorded in report |

- [ ] Each row is a test using real fixtures from the demo project
- [ ] Engine has 100% branch coverage
- [ ] Policy typo (`job_sucess: true`) fails validation with a clear message, exit 3
