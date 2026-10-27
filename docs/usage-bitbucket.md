# Using ScanProof with Bitbucket Pipelines

Built against real pipelines of public Atlassian repositories.

## Access

```bash
export BITBUCKET_TOKEN=...       # repository / workspace access token (Bearer): pipelines + repository read
# or an API token with your account email:  BITBUCKET_USER=you@example.com  (sent as Basic)
scanproof verify -P policy.yaml --pipeline "$BITBUCKET_BUILD_NUMBER"
```

## Evidence comes from Code Insights

Bitbucket has no public API to download step artifacts. Security pipes (git-secrets-scan, Snyk
and others) publish **Code Insights reports** on the commit instead, and that is what ScanProof
reads, with tool `bitbucket-code-insights`:

```yaml
project: {provider: bitbucket, id: my-workspace/my-repo}
requirements:
  - id: SECRETS
    tool: bitbucket-code-insights
    job_name: Security Scan                     # the step
    report_path: Git secrets Security Scan report   # report title or external id
```

The newest report with that title on the pipeline's commit is used, with all its annotations as
findings. A PENDING report is not accepted. Code Insights reports belong to the **commit**, not
to a step, so a report from another run on the same commit also counts.

## What ScanProof detects

| Situation | ScanProof |
|---|---|
| Step FAILED in a pipeline that still succeeded (`on-fail: strategy: ignore`) | BLOCKED `FAILURE_MASKED_BY_ALLOW_FAILURE` |
| Step FAILED / ERROR / STOPPED / NOT_RUN | BLOCKED `JOB_NOT_SUCCESS` |
| Manual step not run yet (pipeline paused) | `manual` |
| Report title not found on the commit | BLOCKED `REPORT_MISSING` |
| Pagination link pointing off api.bitbucket.org | INDETERMINATE (refused) |
