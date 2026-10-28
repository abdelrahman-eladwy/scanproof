## What changed

Describe the smallest behavior change and link the tracking issue (or a private advisory without exposing confidential details).

## Security and release impact

- [ ] I classified impact as **P0/P1/P2**, explained the release consequence and checked that no default/production false VERIFIED path is introduced.
- [ ] I considered malformed, missing, unreadable and hostile input where relevant.
- [ ] Any new exploitable security details are reported **privately**, not reproduced in this public PR.

## Tests and verification

- [ ] For a confirmed bug, I linked a regression test that **failed before** the fix and passes afterward. For non-bug changes, explain which behaviors were validated.
- [ ] Relevant positive and negative decision/exit-code cases are covered.
- [ ] All six PR jobs are green (3.12, 3.13, lowest core, lowest attestations, installed wheel, non-root Docker).
- [ ] I updated affected contracts/docs and the [defect ledger](docs/development/defect-triage.md) if a recorded bug changed.
- [ ] I identified any live provider contract needed to verify this change, or documented why none applies.

**Merge responsibility:** do not merge failing PRs. After merge, verify `main` CI and record the run and SHA in the issue. Passing unit tests alone never prove independent deployment-gate enforcement.
