# Using ScanProof with GitHub Actions

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
      - uses: actions/checkout@v5
      - run: pip install scanproof
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

Verified against real runs in `.github/workflows/github-contract.yml`, where ScanProof checks its
own run on every change:

| Situation | What the GitHub API shows | ScanProof |
|---|---|---|
| Scan step fails under **step** `continue-on-error` | job **success**, step **success** | BLOCKED: `FAILURE_MASKED_BY_ALLOW_FAILURE` (found via the job's failure annotation) |
| Scan job fails under **job** `continue-on-error` | job failure, run success | BLOCKED: `FAILURE_MASKED_BY_ALLOW_FAILURE` |
| Scan job skipped by `if:` | job skipped | BLOCKED: `JOB_NOT_SUCCESS` |
| Token lacks `checks: read` | annotations 403 | INDETERMINATE: `STEP_MASKING_UNKNOWN` |
| Artifact bytes differ from GitHub's digest | — | BLOCKED: report unparseable (digest mismatch) |
| Re-run attempts | jobs from every attempt | latest attempt is judged; retries are reported |
