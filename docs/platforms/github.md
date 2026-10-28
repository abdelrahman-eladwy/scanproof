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
the workflow can remove the gate (same trust boundary as on GitLab, see docs/security.md).

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
| Workflow still running | job `in_progress` | INDETERMINATE: `JOB_NOT_FINISHED` |

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
