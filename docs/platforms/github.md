# Using ScanProof with GitHub Actions

> **Before v0.1.0 is released** there is no PyPI package or container image yet. Until then install
> from source with `pip install "git+https://github.com/abdelrahman-eladwy/scanproof"` and build the
> image yourself with `docker build -t scanproof .` from a checkout.

## Token permissions

| Permission | Why |
|---|---|
| `actions: read` | runs, jobs, artifacts |
| `checks: read` | check-run annotations, the **only** place GitHub records a step that failed under `continue-on-error` (see below) |

Inside a workflow, `${{ github.token }}` with the job-level `permissions:` above is enough. Outside
GitHub, use a fine-grained PAT with *Actions: read* and *Checks: read* on the repository, in
`GITHUB_TOKEN` (or `--token-env`).

## Policies for GitHub

GitHub artifacts belong to the **run**, not to a job, so every requirement names the artifact that
holds the report:

```yaml
apiVersion: scanproof.dev/v1alpha1
kind: PipelineAssurancePolicy
project: {provider: github, id: my-org/my-app}
requirements:
  - id: SAST-001
    tool: semgrep
    job_name: sast                 # job whose result must be success
    artifact_name: semgrep-report  # actions/upload-artifact `name:`
    report_path: semgrep.json      # path inside that artifact
    checks: {scanner_errors_allowed: 0, minimum_scanned_files: 1}
```

ScanProof downloads the artifact zip, checks it against the **sha256 digest GitHub recorded** for
the artifact (a mismatch blocks), and reads only `report_path` from it, with size limits.

Limitation: because artifacts aren't tied to jobs, ScanProof cannot prove *which* job uploaded the
artifact; it proves the artifact came from the verified run and commit.

## Gate a deployment

```yaml
jobs:
  sast:
    # ... runs semgrep, then actions/upload-artifact with name: semgrep-report
  scanproof:
    needs: [sast]
    runs-on: ubuntu-latest
    permissions: {contents: read, actions: read, checks: read}
    steps:
      - uses: actions/checkout@v5        # pin to a commit SHA in real workflows
      - run: pip install scanproof          # until v0.1.0: pip install "git+https://github.com/abdelrahman-eladwy/scanproof"
      - run: scanproof verify -P .scanproof/policy.yaml --pipeline "${{ github.run_id }}" -o scanproof-report.json
        env:
          GITHUB_TOKEN: ${{ github.token }}
  deploy:
    needs: [scanproof]           # only after VERIFIED (exit 0)
    # ...
```

Protect the policy and this workflow with CODEOWNERS and branch protection: anyone who can edit
the workflow can remove the gate (same trust boundary as on GitLab, see docs/security.md). For a
**required merge check**, that is not enough on its own; see the next section.

## Make the required check independent of the pull request

A `pull_request` workflow runs the **pull request's own copy** of the workflow. A PR can
therefore rewrite the gate job (e.g. `run: exit 0`), its policy, its scanner rules or the report,
and still produce a green check with the gate's name. Pinning the required check to the GitHub
Actions app does not help, because **every** workflow's checks come from that same app. This was
demonstrated live: a forged `ScanProof verification` reported success
([gate-lab #15/#18](https://github.com/abdelrahman-eladwy/scanproof-gate-lab/issues/13)), and
only code-owner review stood in the way.

The pattern below makes the required check something only the protected branch can produce:

| Piece | Why |
|---|---|
| `on: pull_request_target` | the workflow, `.scanproof/policy.yaml` and scanner rules always come from the base branch; PR edits to them are ignored |
| PR head checked out into `pr/` **as data only** | scanners read files; nothing from the PR is built, installed or executed |
| Delete PR-supplied scope files before scanning | e.g. a nested `.semgrepignore` hides files from Semgrep even with `--no-git-ignore`; `.trivyignore*`, `trivy.yaml` likewise. Add `--disable-nosem` (Semgrep) and each tool's equivalent ([#123](https://github.com/abdelrahman-eladwy/scanproof/issues/123)) |
| `scanproof verify` on this run, base policy, `--settle-seconds 120` | GitHub can report finished `needs:` jobs as queued for over 45s under load ([#118](https://github.com/abdelrahman-eladwy/scanproof/issues/118)) |
| A dedicated **GitHub App** (Checks: read & write only) posts the result on the PR head SHA | its private key is an **environment** secret in an environment whose deployment branches are **only the protected branch**, so no PR workflow can read it |
| Ruleset requires that check **with the App's ID as source** | a check of the same name from any other app or workflow does not satisfy it |

```yaml
on:
  pull_request_target:
    types: [opened, synchronize, reopened]
permissions: {}
jobs:
  scan-semgrep:                    # job name = policy job_name
    runs-on: ubuntu-latest
    container: semgrep/semgrep:<pinned>
    permissions: {contents: read}  # no secrets, no environment
    steps:
      - uses: actions/checkout@<sha>                # base: rules + policy
        with: {persist-credentials: false}
      - uses: actions/checkout@<sha>                # PR head, data only
        with: {ref: "${{ github.event.pull_request.head.sha }}", path: pr, persist-credentials: false}
      - run: find pr -name .semgrepignore -type f -print -delete
      - run: semgrep scan --config .semgrep/rules.yml --disable-nosem --json --output semgrep.json pr/src/
      - if: ${{ always() }}
        uses: actions/upload-artifact@<sha>
        with: {name: semgrep-report, path: semgrep.json}
  verify:
    needs: [scan-semgrep]
    if: ${{ always() }}
    runs-on: ubuntu-latest
    permissions: {contents: read, actions: read, checks: read}
    steps:   # base checkout only; never the PR ref
      - uses: actions/checkout@<sha>
        with: {persist-credentials: false}
      - run: pip install scanproof
      - run: scanproof verify -P .scanproof/policy.yaml --pipeline "$GITHUB_RUN_ID" -p "$GITHUB_REPOSITORY" --settle-seconds 120
        env: {GITHUB_TOKEN: "${{ github.token }}"}
  sign:
    needs: [verify]
    if: ${{ always() }}
    runs-on: ubuntu-latest
    environment: gate-signer       # deployment branches: the protected branch only
    permissions: {}
    steps:
      - id: app
        uses: actions/create-github-app-token@<sha>
        with:
          client-id: ${{ vars.GATE_APP_CLIENT_ID }}
          private-key: ${{ secrets.GATE_APP_PRIVATE_KEY }}   # environment secret
          permission-checks: write
      - run: |   # fail closed: only an explicit verify success passes
          [ "$R" = success ] && c=success || c=failure
          gh api "repos/$GITHUB_REPOSITORY/check-runs" -f name="ScanProof signed verification" \
            -f head_sha="$SHA" -f status=completed -f conclusion="$c"
        env:
          GH_TOKEN: ${{ steps.app.outputs.token }}
          SHA: ${{ github.event.pull_request.head.sha }}
          R: ${{ needs.verify.result }}
```

A complete, tested version with a second scanner (Trivy) and offline contract tests is in
[scanproof-gate-lab](https://github.com/abdelrahman-eladwy/scanproof-gate-lab/blob/main/.github/workflows/scanproof-signed-gate.yml).

**Settings checklist**

- Ruleset on the default branch: require pull requests, code-owner review, *approval of the most
  recent reviewable push*, and the status check `ScanProof signed verification` **with the App as
  source**; strict status checks; empty bypass list. Read it back as an administrator: in our test `bypass_actors` was returned to an
  administrator but omitted for a workflow `GITHUB_TOKEN`, so treat a missing field as unknown,
  never as an empty list.
- Environment `gate-signer`: deployment branches = *Selected* → the default branch only. Store the
  key as an **environment** secret; repository secrets are readable by same-repository PR workflows.
- Deployment environments: "protected branches only" is documented in terms of classic branch
  protection rules; with rulesets alone, an unprotected branch was able to create a staging
  deployment. Prefer *Selected branches* naming the default branch.
- CODEOWNERS on `.github/workflows/`, `.scanproof/` and scanner configuration.

**What was demonstrated on GitHub** (gate-lab, October 30, 2026; evidence in
[gate-lab#13](https://github.com/abdelrahman-eladwy/scanproof-gate-lab/issues/13)):

| Pull request | In-repo check | Signed check | Merge |
|---|---|---|---|
| Forges the in-repo gate and deletes all scanned code | success (forged) | **failure** | **405**: "Required status check "ScanProof signed verification" is failing" |
| Adds `.semgrepignore` hiding all Python | failure (honoured the ignore) | **success** (ignore neutralised) | — |
| Legitimate change, approved | success | success | merged; staging deployed only after the required environment reviewer (not the initiator) approved |

**Limits.** This moves trust to whoever controls the protected branch and the `gate-signer`
environment; it does not create independence from them. Review by a separately controlled
person is still required for that. `pull_request_target` runs with base-branch privileges: never
build, install or execute PR content in it, and keep the PR checkout out of every job that holds a
secret. Scanners that only *count* what they were told to skip cannot see files skipped before the
scan; pair base-owned scope with `checks.suppressed_findings_allowed` where the report records
suppressions (see [scan types](../scan-types.md#suppressed-findings-suppressed_findings_allowed)).

## What ScanProof detects on GitHub

Verified against real runs in the [`github-contract` workflow](https://github.com/abdelrahman-eladwy/scanproof-e2e/blob/main/.github/workflows/github-contract.yml), where
ScanProof checks its own run daily against `main`:

| Situation | What the GitHub API shows | ScanProof |
|---|---|---|
| Scan step fails under **step** `continue-on-error` | job **success**, step **success** | BLOCKED: `FAILURE_MASKED_BY_ALLOW_FAILURE` (found via the job's failure annotation) |
| Scan job fails under **job** `continue-on-error` | job failure, run success | BLOCKED: `FAILURE_MASKED_BY_ALLOW_FAILURE` |
| Scan job skipped by `if:` | job skipped | BLOCKED: `JOB_NOT_SUCCESS` |
| Token lacks `checks: read` | annotations 403 | INDETERMINATE: `STEP_MASKING_UNKNOWN` |
| Artifact bytes differ from GitHub's digest | — | BLOCKED: report unparseable (digest mismatch) |
| Re-run attempts | Jobs from every attempt; gate-only reruns can synthesize new IDs for scans executed before the attempt started | Earlier-attempt successful jobs with unverifiable masking are INDETERMINATE (`STEP_MASKING_UNKNOWN`), not VERIFIED; rerun scans with the gate |
| Matrix job, one instance masked | `sast (python)` success, `sast (go)` success + failure annotation | BLOCKED: `job_success [sast (go)]` |
| Job in a reusable workflow | `caller / sast` | matched by `job_name: sast` |
| Leg removed from the matrix, `instances: [py, js]` declared | only `sast (py)` ran | BLOCKED: `job_present [sast (js)]` `REQUIRED_INSTANCE_ABSENT` |
| Reusable-workflow caller removed, `copies: [api, web]` declared | only `api / sast` ran | BLOCKED: `job_present [web / sast]` `REQUIRED_COPY_ABSENT` |
| Workflow still running | job `in_progress` | INDETERMINATE: `JOB_NOT_FINISHED` (after the `--settle-seconds` re-reads, default 30s) |

`job_name` matches the job exactly, its matrix instances (`name (...)`) and its name inside a
reusable workflow (`caller / name`); when several match, every one must pass. That includes the
exact-name job: a passing `sast` does not stand in for a failing `sast (py)` or `caller / sast`
([#59](https://github.com/abdelrahman-eladwy/scanproof/issues/59)). Matrix names carry no
total, so declare the legs that must run, `instances: [py, go]`: a leg removed from
`strategy.matrix` is then a FAIL (`REQUIRED_INSTANCE_ABSENT`), and `assurance.profile:
production` requires the declaration
([#60](https://github.com/abdelrahman-eladwy/scanproof/issues/60),
[details](../advanced-policy.md#matrix-legs-declare-the-instances-that-must-run)). Several
callers of one reusable workflow (`api / sast`, `web / sast`) have no total either: declare
them, `copies: [api, web]`, to make a removed caller a FAIL; `production` requires it
([#65](https://github.com/abdelrahman-eladwy/scanproof/issues/65), [details](../advanced-policy.md#prefixed-copies-declare-the-copies-that-must-run)). Legs are
recognized by GitHub's default form, `sast (py, 3.12)`. A custom `name:` is a leg only if it
has that form (`name: sast (${{ matrix.lang }})`); with any other form, such as
`sast-${{ matrix.lang }}`, GitHub appends nothing and each leg is a job of its own name. All matrix
instances share the one `artifact_name` you give, so give each instance its own artifact (e.g.
`semgrep-${{ matrix.lang }}`) and one requirement per artifact if each report must be checked.

GitHub keeps only a limited number of annotations per step and per job (in our live run, 10 of
150 warnings from one step). ScanProof still reads every annotation page, and treats a list it
cannot finish reading as UNKNOWN.

### Gate-only reruns and inherited scan jobs

A `Re-run jobs` action on **only the ScanProof gate job** creates a new GitHub
`run_attempt` while leaving earlier scan executions in place. In a real October 28, 2026
run, GitHub exposed synthetic attempt-2 job records with fresh IDs but `started_at`
timestamps *before* the new attempt's `run_started_at`. Those synthetic jobs no
longer carried the original failure annotations for step-level `continue-on-error`;
before [#90](https://github.com/abdelrahman-eladwy/scanproof/issues/90), ScanProof
returned VERIFIED for masked failures.

For a rerun, ScanProof requires a successful scan job to have started **during**
the current attempt before considering empty annotations as evidence of no masked
failure. A job that predates the attempt (or lacks usable attempt timestamps) is
`STEP_MASKING_UNKNOWN` / INDETERMINATE. A visible failed job remains BLOCKED.
This is deliberate fail-closed behavior: rerun the **scan jobs and gate** in the
same attempt, or use trusted signed evidence with explicit attempt binding. A
gate-only rerun is not a substitute for a successful fresh scan.

This validation checks the provider's attempt timestamps; it does not make
GitHub annotations an independently signed proof of scanner completeness.
