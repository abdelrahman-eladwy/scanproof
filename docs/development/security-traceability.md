# Security invariants, supported surface, and evidence traceability

**Status:** working assurance register for [#44](https://github.com/abdelrahman-eladwy/scanproof/issues/44) and [#83](https://github.com/abdelrahman-eladwy/scanproof/issues/83), **not** a release certification. Updated against core `main` at `9d2f158` (2026-10-28). The inventory below describes implemented behavior, not a promise that every provider, scanner version, or protection mechanism is production-qualified.

## Source-grounded interface inventory

**CLI command inventory:** `inspect`, `evidence`, `attestation`, `validate`, `verify`, `verify-release`.

| Command | Boundary and purpose |
|---|---|
| `inspect` | Reads a provider pipeline/job graph; JSON is an inspection, **not** a release authorization |
| `evidence` | Parses local or downloaded untrusted scanner output; parsing is not proof of scanner execution |
| `attestation` | Verifies a supplied Sigstore bundle and displays claims; no pipeline gate on its own |
| `validate` | Validates policy structure and, with `--explain`, reveals assurance-weakening choices; **not** an enforcement control |
| `verify` | Joins API metadata, report evidence, optional attestations and policy into a decision; the calling platform must enforce its exit code |
| `verify-release` | Aggregates per-component pipeline decisions; a component that cannot be verified remains INDETERMINATE |

Sources: `src/scanproof/cli.py`, `src/scanproof/verification.py`, `src/scanproof/release.py`. CLI contract: VERIFIED = exit 0, BLOCKED = 1, INDETERMINATE = 2, usage/policy error = 3. An error from an unavailable provider is **not** equivalent to a known policy violation.

**Provider ID inventory:** `gitlab`, `github`, `azure-devops`, `jenkins`, `bitbucket`.

| Provider | Implemented reader | Trust/qualification note |
|---|---|---|
| `gitlab` | `src/scanproof/connectors/gitlab.py` | Root and reachable child pipelines; API/bridge limits and inaccessible children can make required copies UNKNOWN. Live child/matrix contracts exist, but do not establish independent protected-gate enforcement |
| `github` | `src/scanproof/connectors/github.py` | Run attempts, checks, artifacts and optional attestations; reusable workflow copies; live contracts exist, but a mutable workflow is not a protected gate |
| `azure-devops` | `src/scanproof/connectors/azure_devops.py` | Public API collection and offline connector tests; no verified, independently protected release-gate acceptance record |
| `jenkins` | `src/scanproof/connectors/jenkins.py` | Live throwaway-Jenkins workflow plus offline tests; does not prove a protected production Jenkins controller |
| `bitbucket` | `src/scanproof/connectors/bitbucket.py` | Public API collection and offline connector tests; no verified protected deployment-gate acceptance record |

All five use `src/scanproof/connectors/http.py` for origin-restricted credentials, bounded redirects, response/ZIP limits, retries and time budgets. **Implemented support is not the same as a validated production configuration.** See `docs/platforms/`, `docs/security.md` and `docs/compatibility.md` for provider/scanner limitations.

**Adapter tool ID inventory:** `semgrep`, `trivy`, `gitlab-sast`, `gitlab-container-scanning`, `sarif`, `cyclonedx`, `gitlab-dependency-scanning`, `gitlab-secret-detection`, `checkov`, `fortify`, `sonatype-iq`, `bitbucket-code-insights`, `gitleaks`, `grype`, `osv-scanner`, `snyk`, `kubescape`, `zap`, `nuclei`.

The 19 registered IDs are defined in `src/scanproof/scanners/__init__.py`; this is a registry count, **not** 19 independently proven scanner-completeness guarantees. `fortify` and `sonatype-iq` are **experimental**. `trivy` handles both filesystem and image output. `sarif` is a format and must be constrained by `checks.expected_scanner` where the producer matters. Missing scope/error fields remain UNKNOWN, not zero. For per-format limitations and tested versions see [scanner compatibility](../compatibility.md) and [scan types](../scan-types.md).

### Security-sensitive policy choices

| Field(s) | Default / risk / condition |
|---|---|
| `assurance.profile` | `compatible` by default; `production` rejects recognized weakening options at **load time**, not malicious edits to the policy file itself |
| `assurance.minimum_level` | `report` by default; `reported_scope` checks the scanner's **claim**, not independent coverage |
| `enforcement.on_unknown` / `on_nothing_applicable` | `block` / `block`; `warn` / `allow` are explicit fail-open opt-ins rejected by `production` |
| `checks.job_success`, `same_commit`, `report_required` | All default `true`; disabling them weakens proof and is rejected by `production` |
| `checks.minimum_scanned_files`, `required_paths`, `scanner_errors_allowed`, `ignore_scanner_warnings`, `minimum_components`, `minimum_resources`, `expected_scanner` | Scanner-reported metrics and identity; availability depends on adapter format, so absent fields cannot be inferred as a clean scan |
| `checks.image_digest_must_match`, `same_target_as`, `target_url_must_match`, `minimum_endpoints`, `max_age_hours` | Explicit target binding/freshness options; mutable image tags are not a substitute for a digest |
| `requirements[].applies_to.refs` | Unknown provider ref is UNKNOWN for scoped requirements, not automatically not-applicable |
| `requirements[].instances` / `copies` | Optional declarations of matrix legs and downstream/caller copies. Under `production`, undeclared observed instances/copies are UNKNOWN; a leg or copy that never existed cannot be inferred without a declaration |
| `requirements[].attestation` (`source`, `subject`, `predicate_type`, `signer`, `same_commit`, `same_run`) | Optional Sigstore proof; signer identity and run/attempt pinning matter; `production` rejects disabling commit/run bindings or leaving the repository unpinned |
| `waivers[]`, `enforcement.max_waiver_days` | Waivers are visible, targeted and expiry checked. **`approved_by` is a policy-file assertion, not independently verified approver authorization.** The production profile bounds duration and forbids waiving key presence/declaration checks, but file ownership must be protected externally |

Sources: `src/scanproof/policy/models.py`, `src/scanproof/policy/profile.py`, `src/scanproof/policy/engine.py`; details in [advanced policy](../advanced-policy.md). Unknown policy fields are rejected by the schema.

## Trust boundaries and abuse cases

| Boundary / actor-controlled surface | Misuse scenario | Required outcome / remaining qualification |
|---|---|---|
| Policy YAML and CI workflow controlled by application author | Remove ScanProof, change required check name, set `on_unknown: warn`, remove a requirement | Weakening switches rejected by `production` when policy is evaluated; **removing the gate must be blocked by independent provider rules (not yet demonstrated)** |
| Provider API and authorization | 401/403/429, timeouts, pagination loop, partial/inaccessible child graph | Unknown/INDETERMINATE, never VERIFIED for evidence that may be missing; tests: `test_hostile_providers.py`, `test_declared_copies.py` |
| Job inventory | Skip/delete scan, `allow_failure` mask, remove matrix leg, remove downstream/reusable copy | Known absence/failure BLOCKED; unreadable possible location UNKNOWN; unknown number of legs/copies needs explicit declaration: `test_adversarial_decision_matrix.py`, `test_declared_instances.py`, `test_declared_copies.py` |
| Report bytes and scanner-controlled fields | Forged/wrong-tool/empty/truncated report, fake success, fake scope | Parse/error/scope checks cannot silently imply proof; without an attestation a privileged runner can forge a parseable report |
| Commit and deployment target | Stale report, wrong commit, mutable tag switched to new digest, wrong DAST URL | Commit/age/digest/URL checks **when configured**; do not claim deploy-target binding if no immutable digest/URL check was specified |
| Signature bundles and trust material | Altered report, replay from other repository/run/attempt, retired CA/log key, trust root inaccessible | Invalid signatures/mismatches fail, unverifiable trust UNKNOWN; offline and live fixture tests do **not** establish ownership of the signing workflow |
| ScanProof output and enforcement | Ignore nonzero exit, `continue-on-error`, skip deploy dependency, delete workflow | An observed decision alone cannot stop deployment; platform branch/ruleset/environment approval and bypass tests must enforce it |

## Invariant-to-evidence matrix

IDs map **one-to-one** to the seven invariants in [the production-readiness roadmap](production-readiness.md#product-contract-and-architectural-boundaries). The listed owner is the code/security responsibility, not a person or GitHub CODEOWNER. A live workflow reference means a test harness exists; **not** that it was re-run on the current core commit or that platform protection was audited.

| ID / invariant | Responsible module | Offline regression tests | Live validation route and status | Documentation / release evidence |
|---|---|---|---|---|
| **INV-01** VERIFIED requires satisfied applicable checks or visible valid waiver | `src/scanproof/policy/engine.py` | `tests/unit/test_policy.py`, `tests/unit/test_serialization_properties.py`, `tests/unit/test_advanced_policy.py` | `scanproof-e2e/.github/workflows/release-gate-contract.yml` (negative gate decision, **not** independent protection); platform enforcement pending #45 | [advanced policy](../advanced-policy.md); core CI run #40679918810 |
| **INV-02** Missing/ambiguous/unreadable/stale/unparseable evidence never silently PASS | `src/scanproof/inspection.py`, `src/scanproof/verification.py` | `tests/unit/test_false_verified_paths.py`, `tests/unit/test_provider_error_matrix.py`, `tests/unit/test_declared_copies.py`, `tests/unit/test_hostile_providers.py` | `scanproof-e2e/.github/workflows/copies-contract.yml` and `gitlab-contract.yml` (historical runs; refresh for release) | [security](../security.md); core CI + historical e2e #40667322251 |
| **INV-03** Fail-open switches explicit and forbidden under hardened profile | `src/scanproof/policy/profile.py`, `src/scanproof/policy/models.py` | `tests/unit/test_production_profile.py`, `tests/unit/test_assurance_profile.py` | `scanproof-e2e/.github/workflows/copies-contract.yml` (compatible and production cases); external protected policy ownership pending #26 | [advanced policy](../advanced-policy.md); core CI run #40679918810 |
| **INV-04** Reported scope is not independently proven coverage | `src/scanproof/evidence/models.py`, `src/scanproof/policy/engine.py` | `tests/unit/test_assurance_profile.py`, `tests/unit/test_scan_types.py`, `tests/unit/test_false_verified_paths.py` | `scanproof-e2e/.github/workflows/release-gate-contract.yml` tests scope claims; **independent completeness cannot be proven by report alone** | [scan types](../scan-types.md), [security](../security.md); limited claim |
| **INV-05** Bind evidence to commit, run/attempt and deploy target where applicable | `src/scanproof/attestation/verify.py`, `src/scanproof/policy/engine.py` | `tests/unit/test_attestation_e2e.py`, `tests/unit/test_attestation_trust_windows.py`, `tests/unit/test_verify_scenarios.py` | `scanproof-e2e/.github/workflows/attestation-contract.yml` produces real GitHub attestations; GitLab signing not live-validated | [attestations](../attestations.md), [scan types](../scan-types.md); **conditional** on required attestation/check configuration |
| **INV-06** Network/redirect/auth failures never leak credentials or authorize release | `src/scanproof/connectors/http.py`, provider connectors | `tests/unit/test_hostile_providers.py`, `tests/unit/test_provider_error_matrix.py`, `tests/unit/test_github_connector.py`, `tests/unit/test_gitlab_connector.py` | `scanproof-e2e/.github/workflows/gitlab-contract.yml` and `platforms-contract.yml` exercise real APIs; check credentials in gated staging before qualification | [security](../security.md); core CI run #40679918810 |
| **INV-07** Independent provider protection enforces gate even if workflow mutable | **Outside ScanProof**: provider rulesets, protected environment, central policy & reviewer roles; ScanProof `src/scanproof/cli.py` exposes exit status | `tests/unit/test_cli.py` only tests exit behavior; **no unit test can prove provider-admin protection** | **OPEN**: maintainer-configured protected GitHub/GitLab staging bypass matrix in [#25](https://github.com/abdelrahman-eladwy/scanproof/issues/25), [#26](https://github.com/abdelrahman-eladwy/scanproof/issues/26), [#45](https://github.com/abdelrahman-eladwy/scanproof/issues/45) | [protected gates](../protected-release-gates.md); **no qualifying live enforcement evidence yet** |

### Validation and release-evidence ledger

- **Core post-merge reference:** `main` `9d2f15842af51da975822f1b576f46fa12d14b91`, [CI run #40679918810](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40679918810), six jobs successful including wheel and non-root Docker; this proves those tests ran, not that a protected deployment was enforced.
- **Historical live copies contract:** [scanproof-e2e run #40667322251](https://github.com/abdelrahman-eladwy/scanproof-e2e/actions/runs/40667322251), against older core `b02cae0`, with GitLab/GitHub copy cases; **not** evidence that current core `main` has been retested live.
- **Live workflow definitions:** [scanproof-e2e](https://github.com/abdelrahman-eladwy/scanproof-e2e) `github-contract.yml`, `gitlab-contract.yml`, `copies-contract.yml`, `attestation-contract.yml`, `platforms-contract.yml`, `release-gate-contract.yml`. Workflow existence alone does not constitute a green run or a provider-enforced deployment denial.
- **Unresolved gate:** protected policy ownership and independent negative deployment-bypass trials for both providers are not attested; `#44`, `#45` and `#26` remain open. A signed report is still not proof the signer workflow could not be modified by the same actor.
- **Maintainer action before GO:** bind candidate commit and run IDs; capture API settings for mandatory checks, permissions and CODEOWNERS; attempt the bypasses listed in [protected release gates](../protected-release-gates.md) against staging; verify both successful and rejected deployments; record approver and rollback in `docs/releases/<version>-readiness.md`.

**Drift guard:** `tests/unit/test_security_inventory.py` checks command, provider and adapter registries against the three inventory lines above when the repository docs are present. It does **not** test every invariant or prove correctness, and the installed-wheel suite intentionally lacks repo docs. A green drift guard therefore cannot close the security acceptance gates.
