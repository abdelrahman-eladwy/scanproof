# Defect severity, regression evidence and release disposition

**Status:** maintained defect ledger for [#44](https://github.com/abdelrahman-eladwy/scanproof/issues/44) and [#91](https://github.com/abdelrahman-eladwy/scanproof/issues/91). This is a *sample of confirmed, closed defects* with code and regression ownership, not a complete audit of every historical issue or a production certification. The release candidate still requires an independently protected live gate and a new issue sweep.

## Severity decision contract

Assign the highest credible severity based on the worst supported failure, not on whether a fix is easy:

| Class | Security / release impact | Required handling |
|---|---|---|
| **P0 — release-blocking security** | False **VERIFIED** for required failed/missing/foreign evidence; unauthorised bypass of a mandatory release gate; cross-origin credential disclosure. A crash or denial of service that breaks the gate's security boundary can also be P0 based on demonstrated impact. | Stop release qualification; reproduce safely; fix with negative tests; require independent code review, complete CI and a live validation method for affected providers. Do not accept any open P0 into a release candidate |
| **P1 — correctness or availability** | False **BLOCKED** for legitimate releases; incorrect BLOCKED vs INDETERMINATE classification; critical verified-release availability/operability failures without a proven security bypass. | Prioritize before qualification; require reproducer, regression and operating impact assessment; do not sign off an affected pilot with open P1 |
| **P2 — lower impact** | UX, documentation and routine performance defects that do not undermine the release decision or platform gate. A fail-closed but too-narrow job-name match is P2 unless it materially prevents supported deployments (then reconsider as P1). | Normal prioritization; regression where applicable; include compatibility notes |

**Unknown is not failure.** Network/API permission failure means INDETERMINATE, not a fabricated policy violation. **Compatible profile exceptions are intentional opt-ins:** e.g. `on_unknown: warn` is allowed only with an explicit weak assurance choice and forbidden by `production`. This does *not* reclassify a default/production false VERIFIED as acceptable.

**Disclosure:** Do not put a new, exploitable P0 proof-of-concept, tokens, private workflow URLs or unfixed bypass details in a public issue. Use [GitHub private security advisories](https://github.com/abdelrahman-eladwy/scanproof/security/advisories/new) and publish sanitized tracking information after coordination with maintainers. Closed historical P0 cases in the public tracker are referenced by ID only here.

## Evidence ledger — representative confirmed bugs

Rows are backed by code-level regression tests in the core repo and public GitHub issue classifications. Automated regression evidence for each row comes from its listed test file and the applicable PR/post-merge CI (for the newest GitHub rerun fix, [#92](https://github.com/abdelrahman-eladwy/scanproof/pull/92)). A single historical CI run is **not** evidence for regressions added afterward, nor proof of independently protected provider enforcement. Live acceptance must be recorded separately in the [security traceability register](security-traceability.md).

| Defect | Severity | Regression file(s) | Release disposition |
|---|---|---|---|
| [#23](https://github.com/abdelrahman-eladwy/scanproof/issues/23) scope-free parseable reports lacked a release-grade scope option | P1 (assurance-contract gap) | `tests/unit/test_assurance_profile.py` | Mitigated by **opt-in** `assurance.minimum_level: reported_scope` (PR #24): unknown scope is UNKNOWN, empty scope FAIL; compatible `report` policies remain weaker. Reported scope is still self-attested, not independent proof |
| [#50](https://github.com/abdelrahman-eladwy/scanproof/issues/50) unknown ref and required-path bypass | P0 | `tests/unit/test_false_verified_paths.py` | Fixed; do not weaken scoped policy/ref handling |
| [#59](https://github.com/abdelrahman-eladwy/scanproof/issues/59) exact job hides failed instances | P0 | `tests/unit/test_exact_name_instances.py` | Fixed; all matched jobs must pass |
| [#60](https://github.com/abdelrahman-eladwy/scanproof/issues/60) removed matrix leg not detected | P0 | `tests/unit/test_declared_instances.py` and `tests/unit/test_adversarial_decision_matrix.py` | Fixed with declared legs; unknown total still requires declarations |
| [#65](https://github.com/abdelrahman-eladwy/scanproof/issues/65) removed child/caller copy not detected | P0 | `tests/unit/test_declared_copies.py` and `tests/unit/test_adversarial_decision_matrix.py` | Fixed with declared copies; undeclared copy cardinality cannot be inferred |
| [#88](https://github.com/abdelrahman-eladwy/scanproof/issues/88) missing parallel legs above cap | P0 | `tests/unit/test_parallel_total_bounds.py` | Fixed; completeness never bypassed by an enumeration cap |
| [#90](https://github.com/abdelrahman-eladwy/scanproof/issues/90) gate-only GitHub rerun accepted inherited masking evidence | P0 | `tests/unit/test_github_gate_rerun.py` | Fixed; inherited old-attempt scan jobs cannot silently satisfy masking checks |
| [#68](https://github.com/abdelrahman-eladwy/scanproof/issues/68) pending child incorrectly BLOCKED | P1 | `tests/unit/test_unstarted_downstream.py` | Fixed; pending child is UNKNOWN until observable |
| [#71](https://github.com/abdelrahman-eladwy/scanproof/issues/71) visible job with unreadable child still VERIFIED in production | P0 (re-triaged from historical P1 label) | `tests/unit/test_unbounded_copies.py` | Fixed for production; review waiver/declaration behavior before claiming gate completeness |
| [#62](https://github.com/abdelrahman-eladwy/scanproof/issues/62) qualified child matrix/parallel job falsely absent | P2 (issue label; reconsider P1 if a supported release is blocked) | `tests/unit/test_qualified_instances.py` | Fixed; child-prefix scope stays narrow |
| [#69](https://github.com/abdelrahman-eladwy/scanproof/issues/69) unrelated unreadable child misclassifies missing copy | P2 (issue label; compatible fail-open warning amplifies risk) | `tests/unit/test_declared_copies.py` | Fixed; unreadable scope must be bounded to relevant child |

### Older security/correctness fixes tracked by pull request

Several early fixes were submitted directly as PRs rather than standalone defect
issues. These are **fixed code regressions**, not new claims about protected provider
enforcement. Their source-level test paths are checked automatically just like the
issue-linked rows above. PR numbers are used to avoid incorrectly treating a PR as
a separate issue.

| Fix PR | Severity / affected boundary | Regression file(s) | What the test protects / limitation |
|---|---|---|---|
| [PR #20](https://github.com/abdelrahman-eladwy/scanproof/pull/20) downstream source project | P1 (false BLOCKED) | `tests/unit/test_complex_gitlab.py` | Child-project artifacts, report provenance and bundled attestations must be read from the originating project; live authenticated private artifacts remain unqualified under #25 |
| [PR #21](https://github.com/abdelrahman-eladwy/scanproof/pull/21) future-dated scan completion | P0 (false freshness evidence) | `tests/unit/test_advanced_policy.py` | A job timestamp over five minutes in the future is UNKNOWN, not proof of a fresh scan; freshness requires `max_age_hours` |
| [PR #22](https://github.com/abdelrahman-eladwy/scanproof/pull/22) GitHub signed run replay | P0 (attestation replay) | `tests/unit/test_attestation_e2e.py` | Signed attempt must equal the current workflow-run attempt when `same_run` is required; this alone does not protect the signer workflow |
| [PR #78](https://github.com/abdelrahman-eladwy/scanproof/pull/78) retired trust root | P0 (untrusted signing material) | `tests/unit/test_attestation_trust_windows.py` | Fulcio CA, Rekor and CT trust windows are checked at signing time; signing timestamp/source validation remains a distinct boundary |
| [PR #80](https://github.com/abdelrahman-eladwy/scanproof/pull/80) hostile HTTP pagination/response budgets | P0 candidate (resource-exhaustion/availability) | `tests/unit/test_hostile_providers.py` | Slow-drip responses, inflated API pages and repeating pagination are bounded; no live provider throughput/SLO certification |
| [PR #81](https://github.com/abdelrahman-eladwy/scanproof/pull/81) oversized ZIP directories | P0 candidate (resource-exhaustion) | `tests/unit/test_zip_guard.py` | Excessive archive entry counts/central-directory sizes are rejected before full ZIP parsing; full-system memory ceilings remain to be load-tested |
| [PR #82](https://github.com/abdelrahman-eladwy/scanproof/pull/82) GitLab root trigger-list 404 | P0 (false VERIFIED from incomplete graph) | `tests/unit/test_declared_copies.py` | Root downstream inventory 404 must not hide a failing child copy behind a passing root job; unresolved child access stays UNKNOWN |

**Audit boundary:** This register now covers the explicitly enumerated issue-linked
and early PR-linked regressions, not every historical commit. The evidence
required to close Phase 1 #44 includes an exhaustive confirmed-defect sweep,
red/green regression history where available, and verification of open P0
findings. Source-level test references alone cannot prove past vulnerable code
was exercised or that independent release gates reject malicious bypasses.

**Scope caveat:** Historical labels reflect triage at the time. #71 carried a P1 label despite a reproduced false VERIFIED under `production`, so **this ledger re-triages that fixed issue as P0** based on the invariant, rather than copying the historical label. #88 was experimentally confirmed by a **red** test and fixed in #89; #90 was reproduced against a real GitHub rerun and fixed in #92, with a separate live provider rerun acceptance requirement. All rows are regression-mapped, but this *does not claim that every confirmed bug ever found* has a listed test; that broader inventory remains in #44/#41.

## Required development and release workflow

1. Record a concrete minimal reproducer: policy profile, connector and version, provider response, expected decision/exit code vs observed, threat-boundary impact and redacted artifacts. New exploitable security defects go to a private advisory first.
2. Assign P0/P1/P2 with reasoning, update severity if the reproducible impact changes, and link a GitHub issue or private advisory. For P0, identify affected supported configurations and whether a release must be paused.
3. Add a regression test that fails on the vulnerable revision and proves the specific invariant. Include positive/negative cases and exact decision/exit code. Keep the fix local to the responsible adapter/connector/policy component.
4. Link the test file, issue, fix PR and release impact in this ledger or the traceability register. A closed issue alone is **not** test evidence.
5. Require all six PR checks (3.12, 3.13, both lowest dependency cases, wheel, Docker) green. Never merge a failing PR; verify post-merge `main` CI. Where an external provider is affected, record a live-contract run bound to the target commit before calling that configuration qualified.
6. Before any release candidate, query all open issues/security advisories and re-evaluate unresolved P0/P1, waivers and independent protected deployment-gate bypass scenarios. **No release GO decision based on this table alone.**

The source-only consistency test `tests/unit/test_defect_ledger.py` checks that this documented table keeps working links to local regression tests, a severity and an issue ID. Installed wheel/Docker tests intentionally do not contain repository docs; they exercise the actual code regressions rather than this bookkeeping test.
