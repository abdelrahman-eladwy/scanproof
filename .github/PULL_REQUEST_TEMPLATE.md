## What changed

Describe the smallest behavior change and link the tracking issue ("Closes #123"), or a private advisory without exposing confidential details. One change per PR.

## Security and release impact

- [ ] I classified impact as **P0/P1/P2**, explained the release consequence and checked that no default/production false VERIFIED path is introduced.
- [ ] The [security rules](https://github.com/abdelrahman-eladwy/scanproof/blob/main/CONTRIBUTING.md#security-rules-for-code-changes) still hold, in particular: unknown is never pass.
- [ ] I considered malformed, missing, unreadable and hostile input where relevant.
- [ ] Any new exploitable security details are reported **privately**, not reproduced in this public PR.
- [ ] No new dependency, or the reason is stated above.

## Tests and verification

- [ ] `ruff check . && ruff format --check . && pytest` passes locally.
- [ ] For a confirmed bug, I linked a regression test that **failed before** the fix and passes afterward. For non-bug changes, explain which behaviors were validated.
- [ ] Relevant positive and negative decision/exit-code cases are covered (real, sanitized fixtures for new report or API formats).
- [ ] All six PR jobs are green (3.12, 3.13, lowest core, lowest attestations, installed wheel, non-root Docker).
- [ ] I updated affected contracts/docs, `CHANGELOG.md` for user-visible changes, and the [defect ledger](docs/development/defect-triage.md) if a recorded bug changed.
- [ ] I identified any live provider contract needed to verify this change, or documented why none applies.

**Merge responsibility:** do not merge failing PRs. After merge, verify `main` CI and record the run and SHA in the issue. Passing unit tests alone never prove independent deployment-gate enforcement.
