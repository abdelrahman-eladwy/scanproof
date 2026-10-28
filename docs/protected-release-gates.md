# Protecting ScanProof as a mandatory release gate

**Scope:** deployment enforcement and the CI/CD trust boundary. ScanProof answers
whether the required evidence satisfies the selected policy. **It cannot itself
force a CI provider to execute ScanProof, or stop a repository contributor from
editing the policy or uploading forged unsigned artifacts.**

This guide is a deployment design, **not a claim that the settings below are
already enabled** in this repository or any consumer's organization.

## Threat model

| Attacker action | Why an in-repo gate alone fails | Required independent control |
|---|---|---|
| Delete the ScanProof job or the `deploy.needs` edge | Developer-controlled YAML can remove the check | Required check or centrally enforced pipeline policy |
| Change `on_unknown` to `warn`, remove a requirement, or add a waiver | The gate evaluates the policy it is given | Policy ownership and protected review or external policy |
| Set `continue-on-error` on the gate | A failed job can be ignored | Protected deployment job and mandatory platform-side check |
| Skip the entire workflow with an `if` or paths filter | Skipped jobs can be reported as successful in some status-check arrangements | Always-triggered, required workflow with tested branch-rule behavior |
| Forge a well-formed scanner JSON report | Source-controlled pipelines can upload arbitrary artifact bytes | Pinned workflow provenance, signed evidence, independently controlled scanners |
| Sign evidence in one attempt and replay it in another | Run ID can remain unchanged across reruns | Pin signer, commit, run **and attempt**; do not accept UNKNOWN |
| Run release from an unreviewed ref | Successful checks on a different ref do not authorize deployment | Protected default/release branches and protected environments |
| Swap the image after scanning | Source commit is not the release artifact | Scan and release the **same immutable image digest** |

`assurance.minimum_level: reported_scope` verifies **the scanner report's own
claim of coverage**, not independent proof that every relevant file or asset
was scanned. Use `checks.required_paths`, target digest checks and, where needed,
Sigstore attestations on top of this assurance level.

## GitHub Actions: required project controls

A repository administrator should configure **Settings → Rules → Rulesets**
(or branch protection, where applicable) on `main` and release branches:

1. Require pull requests and review before merging. Enable **Require review
   from Code Owners**; the `.github/CODEOWNERS` file identifies policy,
   workflow and verification-code owners. Merely adding CODEOWNERS does
   **not** require approval.
2. Require the stable **ScanProof verification** status check from a trusted
   GitHub Actions source. Test its exact status-check context and expected
   source before making it mandatory.
3. Disallow bypasses except explicitly audited, narrowly authorized break-glass
   processes; restrict force pushes and branch deletions.
4. Protect production via **Settings → Environments → production** with
   deployment branch/tag restrictions and, where available, reviewer approval.
5. Prevent application contributors from weakening these settings. Separate
   ruleset administrators and policy approvers from application authors.
6. For pull requests, use the least-privileged `pull_request` context. Do not
   run untrusted PR code with a powerful `pull_request_target` token.

### GitHub sample dependency (not enforcement by itself)

```yaml
permissions: {contents: read}

jobs:
  scanproof:
    needs: [semgrep, trivy]
    if: ${{ always() }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      checks: read
      attestations: read  # only if attestation source: platform
    steps:
      - uses: actions/checkout@<PINNED_COMMIT_SHA>
        with:
          persist-credentials: false
      - name: Verify required scans
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          python -m pip install "scanproof==<REVIEWED_VERSION>"
          scanproof verify --provider github \
            -p "$GITHUB_REPOSITORY" \
            --pipeline "$GITHUB_RUN_ID" \
            -P .scanproof/policy.yaml

  deploy:
    needs: [scanproof]
    if: ${{ needs.scanproof.result == 'success' }}
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: echo "Replace with approved deployment action"
```

**Replace the placeholders** with reviewed release artifacts and approved
action SHAs. The sample has no real scanner jobs or deployment action and must
not be mistaken for a copy-paste-ready deployment workflow. In a genuine
protected setup, use an immutable external policy location or policy reviewed
by a separate team; the in-repo YAML here is illustrative.

The `if: always()` keeps the gate observable if an upstream job fails, but
a contributor can still delete it without a **platform-enforced required check**.
Use platform-enforced status checks and environments as the real guardrail.

## GitLab: centrally managed controls

1. Manage mandatory verification with a **pipeline execution policy** or
   equivalent centrally managed policy controlled by the security team.
   A protected `include:` is **not enough** by itself: someone who can edit
   `.gitlab-ci.yml` may remove the include.
2. Enforce merge approvals / CODEOWNERS on the policy project and CI definition.
   Restrict changes to deployment branches, tags and protected environments.
3. Protect the verification token as a masked/protected CI variable; scope it to
   the minimum `read_api` and artifact access necessary. Do not pass tokens
   as CLI arguments or write them to artifacts.
4. Do not permit `allow_failure: true` on a mandatory gate. Wire the deploy
   stage so an exit code of **1 (BLOCKED), 2 (INDETERMINATE), or 3 (usage
   error)** prevents deployment.
5. Give policy changes an independent review/approval path, and record any
   break-glass bypass in auditable change management.

**Open validation gap:** real authenticated GitLab security-artifact reads,
multi-project child report and attestation retrieval, and private-CA
self-managed GitLab still need test environments. The existing anonymous
GitLab contract proves pipeline **inspection** only: protected report
artifacts returned HTTP 403.

## Required adversarial acceptance tests

Perform these in a sacrificial repository and staging deployment environment,
never by deliberately weakening production rules. Capture run links and
effective repository/ruleset settings.

- [ ] A contributor PR removes the mandatory ScanProof workflow → **merge/deploy blocked**.
- [ ] A contributor PR changes the policy to `on_unknown: warn` or removes a
      required scanner → **code-owner/policy review required**, or externally
      managed policy remains unchanged.
- [ ] A scanner fails and its job stays green through `continue-on-error` →
      **ScanProof BLOCKED**, deploy cannot run.
- [ ] A report is missing, truncated, stale, unsigned where required, or
      points to another commit/digest → **BLOCKED or INDETERMINATE**, deploy cannot run.
- [ ] A self-verify job is rerun without rerunning its signing step →
      **ATTESTATION_WRONG_RUN**, deploy cannot run.
- [ ] The ScanProof job is skipped / never created → **platform status check
      prevents merge or deploy**. Explicitly test skipped-job behavior.
- [ ] A token cannot read required artifacts → **INDETERMINATE**, deploy blocked.
- [ ] A valid current-attempt, correctly scoped signed scan → **VERIFIED**
      (not a claim that the application has no vulnerabilities).

## Live CI dependency contract (real jobs, no production deployment)

The [`release-gate-contract` workflow](https://github.com/abdelrahman-eladwy/scanproof-e2e/blob/main/.github/workflows/release-gate-contract.yml) in scanproof-e2e
runs only on `fixtures/gate/**` branches or manual dispatch. It creates two
independent scan → gate → deploy dependency chains. Both scan-producing jobs
finish green, but one publishes a Semgrep-shaped JSON report with **no scanned
paths**.

In [live run 40483491063](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40483491063):

| Chain | Gate | Dry-run deployment |
|---|---|---|
| Actual Semgrep scan, nonempty scope | `VERIFIED`, job SUCCESS | Job SUCCESS; marker artifact uploaded |
| Valid JSON but missing scope | `SCAN_SCOPE_UNKNOWN`, `INDETERMINATE` (exit 2), job FAILURE | **SKIPPED** |

The `assert-contract` job independently checked the GitHub Actions `needs`
results, both machine-readable ScanProof reports, and the healthy deployment
marker. It **passed**. The overall workflow was **red by design**, because the
negative gate is a real failing job (no `continue-on-error` wrapper). Do not add
this intentionally failing workflow as a repository's required merge check;
production required checks must be dedicated to the **actual release gate**.

This proves only that, with this unmodified workflow dependency graph,
ScanProof's nonzero exit blocks its downstream job. It **does not prove** that
a developer with workflow-edit privileges cannot remove the gate or change
the policy. That independent platform-enforced protection remains an open
item in [Issue #26](https://github.com/abdelrahman-eladwy/scanproof/issues/26).

## Read-only staging acceptance preflights (not deployment proof)

The [GitHub protected-ruleset preflight](https://github.com/abdelrahman-eladwy/scanproof-e2e/blob/main/docs/github-protected-gate.md) checks the **actual required ScanProof status context and trusted GitHub App**, strict check freshness, CODEOWNER and independent approval, and no observed bypass actors for an active branch rule. The [staging environment preflight](https://github.com/abdelrahman-eladwy/scanproof-e2e/blob/main/docs/github-staging-environment.md) separately checks required deployment reviewers, `prevent_self_review`, protected branch restrictions, and disabled administrator bypass. Both use read-only GitHub API requests and write separate JSON evidence files; denied/invalid API reads never count as a pass.

The [negative-PR evidence observer](https://github.com/abdelrahman-eladwy/scanproof-e2e/blob/main/docs/github-protected-trial-evidence.md) can inspect four sacrificial PRs (valid, missing, failed and skipped gate), but reported GitHub mergeability is **advisory**. Only an actual unauthorized attempted merge and denied staging deployment demonstrate bypass resistance. A successful self-test run **does not mean** the manual ruleset/environment audits have executed.

- GitHub E2E [PR #22](https://github.com/abdelrahman-eladwy/scanproof-e2e/pull/22) merged the environment audit and adversarial configuration checks. Post-merge [preflight CI #40707992324](https://github.com/abdelrahman-eladwy/scanproof-e2e/actions/runs/40707992324) and [demo #40707992244](https://github.com/abdelrahman-eladwy/scanproof-e2e/actions/runs/40707992244) passed. The preflight run's actual target `audit` job was **skipped**, as designed on normal push events.
- The previously observed core [ruleset 25947920](https://github.com/abdelrahman-eladwy/scanproof/rules/25947920) has six generic required CI checks but no required approving or CODEOWNER review and no independently required ScanProof deployment check. The E2E repository's ruleset query observed no repository rulesets. These are **historical configuration observations**, not current protected-deployment evidence.
- **Maintainer/admin dependency:** configure a *sacrificial* GitHub repository with security-owned policy/workflow, independent code review, exact mandatory ScanProof check, and reviewed staging environment. Run both preflights **manually** and retain result JSON, then execute the live negative PR matrix and capture an actual rejected merge plus a blocked staging deployment. Independently validate GitLab's centrally managed pipeline execution policy (GitLab Ultimate) with protected policy ownership and private artifact access. Do not test malicious bypasses against live production deployments.

**This material advances #25, #26 and #45 only; none may be marked completed from offline tests or read-only API observations.**

## Validation evidence and current status

- [GitHub real provider contract with scoped/empty reports](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40477852618):
  a real Semgrep scan passed; scope-free but parseable JSON gave
  `SCAN_SCOPE_UNKNOWN` and exit 2.
- [GitHub attempt replay test](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40481478072/attempts/2):
  a valid signature from attempt 1 was rejected in attempt 2 with
  `ATTESTATION_WRONG_RUN` and exit 1.
- [GitLab public API contract](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40480362948):
  live inspection and fixture publishing passed, but this was anonymous and
  **did not validate private artifact reads**.

**Not yet demonstrated:** organization-enforced branch status checks,
CODEOWNERS approvals, protected deployment environment bypass resistance,
and private GitLab authorization. Treat those as open security acceptance
criteria ([Issue #26](https://github.com/abdelrahman-eladwy/scanproof/issues/26)).
