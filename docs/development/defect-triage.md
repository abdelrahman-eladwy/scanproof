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

Rows are backed by code-level regression tests in the core repo and public GitHub issue classifications. The **CI column** below is the latest [post-merge `main` run #40690689285](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40690689285); the run demonstrates the named test files execute in the suite, not independent platform enforcement. Live acceptance must be recorded separately in the [security traceability register](security-traceability.md).

| Defect | Severity | Regression file(s) | Release disposition |
|---|---|---|---|
| [#50](https://github.com/abdelrahman-eladwy/scanproof/issues/50) unknown ref and required-path bypass | P0 | `tests/unit/test_false_verified_paths.py` | Fixed; do not weaken scoped policy/ref handling |
| [#59](https://github.com/abdelrahman-eladwy/scanproof/issues/59) exact job hides failed instances | P0 | `tests/unit/test_exact_name_instances.py` | Fixed; all matched jobs must pass |
| [#60](https://github.com/abdelrahman-eladwy/scanproof/issues/60) removed matrix leg not detected | P0 | `tests/unit/test_declared_instances.py` and `tests/unit/test_adversarial_decision_matrix.py` | Fixed with declared legs; unknown total still requires declarations |
| [#65](https://github.com/abdelrahman-eladwy/scanproof/issues/65) removed child/caller copy not detected | P0 | `tests/unit/test_declared_copies.py` and `tests/unit/test_adversarial_decision_matrix.py` | Fixed with declared copies; undeclared copy cardinality cannot be inferred |
| [#88](https://github.com/abdelrahman-eladwy/scanproof/issues/88) missing parallel legs above cap | P0 | `tests/unit/test_parallel_total_bounds.py` | Fixed; completeness never bypassed by an enumeration cap |
| [#68](https://github.com/abdelrahman-eladwy/scanproof/issues/68) pending child incorrectly BLOCKED | P1 | `tests/unit/test_unstarted_downstream.py` | Fixed; pending child is UNKNOWN until observable |
| [#71](https://github.com/abdelrahman-eladwy/scanproof/issues/71) visible job with unreadable child still VERIFIED in production | P0 (re-triaged from historical P1 label) | `tests/unit/test_unbounded_copies.py` | Fixed for production; review waiver/declaration behavior before claiming gate completeness |
| [#62](https://github.com/abdelrahman-eladwy/scanproof/issues/62) qualified child matrix/parallel job falsely absent | P2 (issue label; reconsider P1 if a supported release is blocked) | `tests/unit/test_qualified_instances.py` | Fixed; child-prefix scope stays narrow |
| [#69](https://github.com/abdelrahman-eladwy/scanproof/issues/69) unrelated unreadable child misclassifies missing copy | P2 (issue label; compatible fail-open warning amplifies risk) | `tests/unit/test_declared_copies.py` | Fixed; unreadable scope must be bounded to relevant child |

**Scope caveat:** Historical labels reflect triage at the time. #71 carried a P1 label despite a reproduced false VERIFIED under `production`, so **this ledger re-triages that fixed issue as P0** based on the invariant, rather than copying the historical label. #88 was experimentally confirmed by a **red** test and fixed in #89. All rows are regression-mapped, but this *does not claim that every confirmed bug ever found* has a listed test; that broader inventory remains in #44/#41.

## Required development and release workflow

1. Record a concrete minimal reproducer: policy profile, connector and version, provider response, expected decision/exit code vs observed, threat-boundary impact and redacted artifacts. New exploitable security defects go to a private advisory first.
2. Assign P0/P1/P2 with reasoning, update severity if the reproducible impact changes, and link a GitHub issue or private advisory. For P0, identify affected supported configurations and whether a release must be paused.
3. Add a regression test that fails on the vulnerable revision and proves the specific invariant. Include positive/negative cases and exact decision/exit code. Keep the fix local to the responsible adapter/connector/policy component.
4. Link the test file, issue, fix PR and release impact in this ledger or the traceability register. A closed issue alone is **not** test evidence.
5. Require all six PR checks (3.12, 3.13, both lowest dependency cases, wheel, Docker) green. Never merge a failing PR; verify post-merge `main` CI. Where an external provider is affected, record a live-contract run bound to the target commit before calling that configuration qualified.
6. Before any release candidate, query all open issues/security advisories and re-evaluate unresolved P0/P1, waivers and independent protected deployment-gate bypass scenarios. **No release GO decision based on this table alone.**

The source-only consistency test `tests/unit/test_defect_ledger.py` checks that this documented table keeps working links to local regression tests, a severity and an issue ID. Installed wheel/Docker tests intentionally do not contain repository docs; they exercise the actual code regressions rather than this bookkeeping test.
