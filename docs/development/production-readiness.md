# ScanProof production-readiness program

**Status:** proposed plan, not a production-readiness certification.
**Baseline:** v0.1 pre-alpha, Python 3.12/3.13, CLI modular monolith, 5 CI providers,
19 scanner adapters, Sigstore/in-toto attestations. CI passing is necessary but
not sufficient for a secure deployment.

## Product contract and architectural boundaries

ScanProof is an **independent security-scan assurance engine**. It proves only
the claims supported by provider metadata, scanner evidence and, when configured,
verified signatures. It does **not** assert that an application is vulnerability-free,
make vulnerability risk-acceptance decisions, or enforce provider-side deployment
rules by itself. Maintain the current modular monolith:

```text
CLI / policy loading
  -> provider connector (untrusted API and artifacts)
  -> scanner adapter (untrusted report parsing)
  -> normalized evidence / optional signature verification
  -> pure policy engine
  -> immutable decision report / exit code
  -> separately enforced CI or deployment gate
```

Do not introduce a web service, database, message queue, Kubernetes, or
microservices to solve problems the CLI can solve. Future centralized management
must consume versioned decision reports, not duplicate policy logic.

**Invariants (must be covered by tests):**
1. Exit 0 / VERIFIED only when every applicable required check is satisfied or
   covered by a visible, valid, explicitly approved waiver.
2. Missing, ambiguous, unreadable, stale, unparseable, inconsistent, or
   unauthenticated evidence cannot silently count as PASS.
3. Fail-open policy switches are explicit, auditable, and forbidden by the
   hardened production policy profile.
4. A report's claimed scope is not independently proven coverage. Do not
   conflate reported scope with verified scanner completeness.
5. Scan evidence must bind to the intended commit, run/attempt and deploy
   target (immutable image digest when applicable).
6. Network/redirect/authentication failures never leak tokens and never
   authorize a release.
7. The provider's independent protection mechanisms, not a mutable in-repo
   workflow alone, must enforce a mandatory release gate.

## Execution order: no skipping the release gates

### Phase 0 — Baseline, threat model and measurable contracts (P0)

**Goal:** make correctness and release readiness objectively testable.

- [ ] Inventory CLI commands, providers, adapters, trust boundaries and all
      security-sensitive policy options; publish an explicit support matrix.
- [ ] Write misuse/abuse cases: forged reports, policy weakening, missing
      mandatory job, signed replay, compromised runner, partial API visibility,
      stale artifacts, mutable tags, cross-project children and skipped checks.
- [x] Define supported configurations and hardening profiles: default
      backward-compatible behavior versus recommended strict production profile.
      *Evidence:* `assurance.profile: compatible | production` (#52);
      `tests/unit/test_production_profile.py`; docs/advanced-policy.md.
- [ ] Establish reproducible CI baseline: test count, branch coverage, job
      duration, lowest-dependency constraints, Docker smoke and artifact sizes.
- [ ] Classify bugs: P0 false VERIFIED / bypass / credential leak; P1 incorrect
      BLOCKED or unavailable legitimate releases; P2 usability/performance.
- [ ] Create a traceability table: invariant -> automated test -> live contract
      -> documentation -> release evidence.

**Exit gate:** every invariant has an owner/test and a named validation method.
No open P0 security bug is accepted into a release candidate.

### Phase 1 — Fail-closed correctness and trust boundaries (P0)

**Goal:** prevent false assurance under hostile inputs and hostile CI metadata.

- [ ] Differential/adversarial decision tests: absent/skipped/masked jobs,
      report missing/empty/truncated/wrong schema/wrong scanner, zero coverage,
      mismatched commit/image, retries, matrix and downstream jobs.
- [x] Test policy downgrades: `on_unknown: warn`,
      `on_nothing_applicable: allow`, waivers, missing/disabled requirements,
      wildcard/mis-scoped policies; ensure production profile rejects unsafe
      combinations and documentation explains opt-in behavior.
      *Evidence:* #52. One rejection test per opt-in and a compatibility test that it still
      loads without the profile (`test_production_profile.py`); unknown and wildcard refs
      (`test_false_verified_paths.py`); `validate --explain`.
- [x] Attestation negatives: tampered report, foreign signer, wrong repository,
      wrong commit, wrong run **and attempt**, expired/invalid trust material,
      incomplete transparency evidence, replay across projects.
      *Evidence:* trust-root validity windows are now enforced at signing time
      (sigstore-python 4.x does not; `test_attestation_trust_windows.py`); replay across
      projects (`test_attestation_e2e.py`); invalid or empty trust roots fail closed;
      timestamp authorities' windows are enforced by sigstore-python (pinned by a test).
- [x] Hostile provider responses: 401/403/404/429/5xx, pagination cycles,
      unexpected redirects, timeouts, partial downloads, invalid payloads,
      cross-origin token leakage and oversized archives.
      *Evidence:* `test_provider_error_matrix.py`, connector redirect/size/zip tests, and
      `test_hostile_providers.py` (pagination loops, slow-drip deadline, run budget, capped API
      pages, dropped downloads on all five connectors).
- [x] Structured fuzz/property testing for all 19 adapters and the normalized
      evidence/decision serialization, including Unicode, deep nesting,
      malformed archives and compression bombs.
      *Evidence:* seeded adapter fuzz and Unicode stress (`test_robustness.py`,
      `test_scanner_unicode_stress.py`); zip directories capped before `zipfile` opens them
      (`test_zip_guard.py`); gzip bombs stop at the body cap (`test_hostile_providers.py`);
      400 seeded random policy/evidence cases checked for decision, exit-code and strict-JSON
      round-trip properties (`test_serialization_properties.py`).
- [ ] Require regression test for every confirmed bug; prefer a minimal fix in
      the owning connector/adapter rather than adding exception swallowing.

**Status (2026-10-28): exit gate not met.** Remaining work, from a targeted search of
`tests/unit/` (a gap means no dedicated test was found, not that the behavior is wrong):

| Item | Covered | Gap |
|---|---|---|
| Adversarial decisions | `test_adversarial_decision_matrix.py`, `test_false_verified_paths.py`, `test_complex_gitlab.py` / `test_complex_github.py` (retries, masking, matrix, downstream) | **#59 complete:** code fix merged in PR #63; live GitHub contract merged in [scanproof-e2e PR #2](https://github.com/abdelrahman-eladwy/scanproof-e2e/pull/2), and [run #40564240735](https://github.com/abdelrahman-eladwy/scanproof-e2e/actions/runs/40564240735) passed on `main`. **#60 complete:** code merged in PR #64 (post-merge CI [run #40570612599](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40570612599)); declared `instances` make a removed GitLab/GitHub matrix leg a FAIL, and `production` makes undeclared legs UNKNOWN (`test_declared_instances.py`, adversarial rows). Live contracts merged in [scanproof-e2e PR #3](https://github.com/abdelrahman-eladwy/scanproof-e2e/pull/3); the GitLab matrix contract's exact case ignored the exit code ([scanproof-e2e #4](https://github.com/abdelrahman-eladwy/scanproof-e2e/issues/4), fixed in [PR #5](https://github.com/abdelrahman-eladwy/scanproof-e2e/pull/5) with an offline self-test), and [run #40573813183](https://github.com/abdelrahman-eladwy/scanproof-e2e/actions/runs/40573813183) passed on e2e `main` against core `main` @ 206fc07. **#65:** merged in [PR #66](https://github.com/abdelrahman-eladwy/scanproof/pull/66). Live on GitHub: [`copies-contract`](https://github.com/abdelrahman-eladwy/scanproof-e2e/blob/main/.github/workflows/copies-contract.yml) runs two real reusable-workflow callers and 7 scenarios (present, removed caller, production with/without `copies`, compatible warning, two waiver rejections) through a harness that checks exit code, a fresh report, provenance (pipeline id and commit) and exact codes; [run #40579013750](https://github.com/abdelrahman-eladwy/scanproof-e2e/actions/runs/40579013750) on e2e `main`. **GitLab live complete:** child-pipeline and inaccessible-child scenarios ([scanproof-e2e #8](https://github.com/abdelrahman-eladwy/scanproof-e2e/issues/8), [setup](https://github.com/abdelrahman-eladwy/scanproof-e2e/blob/main/docs/gitlab-copies.md)). The first configured run failed closed on HTTP 429 (#74): gitlab.com allows 60 anonymous API requests per hour per IP since 2026-10-19, and a run needs about 66. The contract now reads with a `read_api` token of an account outside the private child project ([E2E PR #11](https://github.com/abdelrahman-eladwy/scanproof-e2e/pull/11)), refuses redirects, and proves on every run that the private child is access-denied: a direct 403/404 check, and ScanProof must report only `svc-private` unreadable, for `AUTH`/`NOT_FOUND` ([E2E PR #12](https://github.com/abdelrahman-eladwy/scanproof-e2e/pull/12)). Post-merge [run #40667322251](https://github.com/abdelrahman-eladwy/scanproof-e2e/actions/runs/40667322251) on e2e `main` @ 62dcc10 against core `main` @ b02cae0: all 8 GitLab scenarios (private child HTTP 404) and all 7 GitHub scenarios passed. **#68 complete:** a not-yet-started downstream pipeline is INDETERMINATE, not BLOCKED ([PR #70](https://github.com/abdelrahman-eladwy/scanproof/pull/70)); the exact rules are in [Missing or unreadable](../advanced-policy.md#missing-or-unreadable-when-absence-is-proven). **#71 complete:** [PR #73](https://github.com/abdelrahman-eladwy/scanproof/pull/73), post-merge [CI #40589582197](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40589582197). **#69 complete:** [PR #75](https://github.com/abdelrahman-eladwy/scanproof/pull/75) scopes uncertainty to the downstream subtrees that could hold a missing path; unrelated private children cannot hide a missing declared copy, also when no declared copy ran (review fix). Post-merge [CI #40667077470](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40667077470). **Still open:** #62. #44 remains open: these changes do not satisfy all phase gates. |
| Attestation negatives | tampered/forged bundles, foreign signer, wrong commit, wrong run and GitHub attempt, missing tlog entries (`test_attestation_verify.py`, `test_attestation_policy.py`, `test_attestation_e2e.py`) | **Closed:** trust material retired before signing time is rejected (CA, Rekor key, CT log; sigstore-python only checked against now), invalid or empty roots fail closed (`test_attestation_trust_windows.py`); a bundle replayed into another project fails the repository pin and the run check, and a GitHub run without its URL is UNKNOWN (`test_attestation_e2e.py`); timestamp authorities' windows are enforced by sigstore-python itself (pinned in `test_attestation_trust_windows.py`) |
| Hostile providers | 401/403/429/5xx on report fetch (`test_provider_error_matrix.py`), redirect loops and downgrades, size limits, zip traversal (connector tests) | **Closed:** a page that repeats or doesn't advance is an immediate `INVALID_RESPONSE` on GitLab, GitHub (jobs, annotations, attestation store) and Bitbucket; every response body (API pages too) is capped and must arrive within `request_deadline` (300 s, not retried), and each connector's requests within `run_budget` (30 min); dropped downloads are retried, then `NETWORK`, on all five connectors (`test_hostile_providers.py`) |
| Fuzz/property | seeded adapter fuzz (`test_robustness.py`), Unicode stress | **Closed:** zip archives (artifacts, Fortify FPRs) with more than 50,000 entries or an 8 MiB central directory are refused before `zipfile` opens them (a 400,000-entry archive took 18 s and 219 MiB); decision and serialization properties over 400 seeded random cases (`test_zip_guard.py`, `test_serialization_properties.py`). Content-Encoding bombs: see Hostile providers |
| Packaged CLI | CI builds the wheel and Docker image, smoke-tests them, and runs the **full unit suite** (adversarial decision matrix included) against each installed copy, never `src/` (`scripts/test_installed.sh`; `SCANPROOF_TEST_INSTALLED=1` makes the run fail if `scanproof` resolves to a source tree) | none known |

**Exit gate:** zero reproducible false VERIFIED cases in the supported threat
model; all known P0 findings fixed with regression tests; red-team matrix
passes on Python 3.12/3.13 and packaged CLI.

### Phase 2 — Independently enforced real release gates (P0)

**Goal:** prove that a developer cannot bypass verification by editing CI YAML.

- [ ] Complete #25: authenticated GitLab private artifact access and
      cross-project child pipelines, plus real GitHub gate cases.
- [ ] Complete #26: configure a sacrificial GitHub repository with required
      checks, CODEOWNERS enforcement, protected branches and protected staging
      environment; capture effective settings and run links.
- [ ] Run negative scenarios: remove gate, skip workflow, weaken policy,
      change required check name, use continue-on-error, remove deploy.needs,
      rerun only the gate, tamper with signed artifact and deny artifact read.
- [ ] Configure an independently managed GitLab pipeline execution policy
      (or equivalent available tier control), and test the same bypasses.
- [ ] Verify protected policy ownership and reviewer separation. Confirm
      read-only provider tokens and rotation/revocation procedures.
- [ ] Keep these tests in sacrificial repos and dry-run/staging environments;
      never deliberately weaken a production repository.

**Exit gate:** live evidence proves both (a) valid evidence can release and
(b) each bypass attempt is rejected by **platform enforcement**. Mark each
provider as validated only for the configuration actually tested. Credentials,
admin settings and staging deployments require maintainer-owned access; an
automated test cannot substitute for those permissions.

### Phase 3 — Reliability, performance and operability (P0/P1)

**Goal:** predictable behavior under realistic enterprise workloads.

- [ ] Define and measure SLO targets on a representative fixture: e.g.
      p95 verification <30s for 100 jobs / 10 reports excluding provider
      rate-limit wait; memory <512 MiB for supported artifact limits. Targets
      are initial proposals and must be adjusted after measurement.
- [ ] Load test large pipelines, 50-way matrices, 2,000+ jobs, pagination,
      downstream graphs, rate limiting, bounded retries and cancellation.
- [ ] Verify resource limits on compressed and decompressed input, timeouts,
      CPU, XML/JSON depth, artifact counts and zip member traversal.
- [ ] Add structured diagnostic codes and safe correlation metadata; ensure
      secrets never appear in errors, output files or logs.
- [ ] Run chaos tests for provider outages and degraded permission scopes.
      Distinguish BLOCKED (known violation) from INDETERMINATE (cannot prove).
- [ ] Provide operational runbooks for 401/403, rate limiting, unknown scope,
      trust root problems, expired waivers and failed deployments.

**Exit gate:** performance budgets met or explicitly documented; no unbounded
resource consumption in supported limits; operational failure paths tested.

### Phase 4 — Stable public interfaces and supply-chain release (P1)

**Goal:** safe installation, upgrades and integration.

- [ ] Define/version JSON report schema and policy schema, document
      compatibility/deprecation and machine-readable stable error codes.
- [ ] Test clean wheel and non-root container from outside source tree,
      supported Python versions, lowest dependencies, offline Sigstore mode
      and supported OS environments.
- [ ] Pin release dependencies and CI actions as appropriate; generate SBOM,
      provenance, signed packages/images and reproducible release evidence.
- [ ] Verify package metadata, PyPI trusted publishing, GHCR public access,
      rollback and release/tag protections; maintainer must perform any
      required account/environment setup.
- [ ] Document upgrades and breaking-change policy; publish versioned
      reference policies for strict and compatibility modes.
- [ ] Run a release-candidate freeze: only severity fixes, independent review,
      full CI, smoke tests and live protected-gate acceptance.

**Exit gate:** a fresh user can install, configure, verify and upgrade from
published artifacts with documented integrity checks and rollback.

### Phase 5 — Customer pilot and production qualification (P1)

**Goal:** prove real customer value and operational safety.

- [ ] Recruit 2–3 design partners with different CI providers; agree on
      non-production/staging pilot scope and success criteria.
- [ ] Run shadow mode before enforcement, measure false BLOCKED/UNKNOWN,
      setup time, scan coverage and investigation time; tune docs/adapters.
- [ ] Turn on mandatory staging gates only after observed results and
      administrator approval; test recovery and emergency change procedure.
- [ ] Complete security review, dependency and license review, vulnerability
      disclosure process, operational ownership and incident response plan.
- [ ] Publish limitations and supported configuration matrix; no generic
      claim of 'tamper-proof', 'no bugs' or 'production-ready everywhere'.

**Exit gate:** signed-off pilot evidence, zero open P0/P1 bugs affecting
supported deployment modes, tested rollback, and a release go/no-go record.
Any exception must be explicit, time-bound, approved and visible.

### Phase 6 — Optional product expansion (P2, after production qualification)

- [ ] Prioritize requests from pilots; first improve diagnostics and templates.
- [ ] Consider read-only centralized audit history/dashboard as a separate
      service consuming versioned reports, with tenancy/RBAC/retention design.
- [ ] Consider vulnerability risk gating as a separately versioned policy
      layer, not a change to the meaning of VERIFIED.
- [ ] Add scanners only with real fixture compatibility, error semantics,
      scope mapping and negative tests.

## Delivery workflow for every change

1. Open a scoped issue with threat, expected behavior, acceptance tests and
   affected trust boundary. Link it to the phase.
2. Reproduce the problem with a failing test or a documented live scenario.
3. Make the smallest design change; update docs and compatibility matrix.
4. Run local static analysis/unit tests, then CI on Python 3.12/3.13,
   lowest dependencies, package and Docker. Keep branch coverage >=90%.
5. Review security invariants and any backwards compatibility impact.
6. Merge through reviewed PR only after all required checks are green.
7. Verify post-merge main workflows and, for trust-boundary changes, repeat
   relevant live staging contract. Update evidence links and issue status.

## Release decision record

Each candidate gets a `docs/releases/<version>-readiness.md` record:
- candidate commit, tag, supported platforms/scanners and trust assumptions;
- CI run links, coverage, performance data, signed artifact digests;
- adversarial test matrix and protected-gate live evidence;
- open issues by severity, risk acceptances and owner/expiry;
- rollback result, operator runbook, security reviewer and maintainer approval;
- **GO / NO-GO** with date and explicit scope.

**No universal bug-free claim is possible.** Production readiness means the
defined threat model, supported configurations, measurable acceptance gates
and residual risks have been validated and approved.
