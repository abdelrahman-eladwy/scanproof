# Using ScanProof with Jenkins

Jenkins Pipelines (declarative and scripted). Verified live against a real Jenkins (2.580.1) that
runs one pipeline per masking pattern ([`platforms-contract`](https://github.com/abdelrahman-eladwy/scanproof-e2e/blob/main/.github/workflows/platforms-contract.yml) in scanproof-e2e).

## Access

A read-only user and an **API token** (Jenkins has no bearer tokens, so ScanProof sends HTTP
Basic `user:token`, only to the Jenkins origin):

```bash
export JENKINS_URL=https://ci.example.com     # or --url
export JENKINS_USER=scanproof-reader          # never as an argument
export JENKINS_TOKEN=...                      # API token
scanproof verify -P policy.yaml --pipeline "$BUILD_NUMBER"
```

The user needs *Job/Read* (and *Overall/Read*). Install **Pipeline Graph View** (stage hierarchy
and step nodes); with only **Stage View** ScanProof falls back to flat stage names.

## Policy

```yaml
project: {provider: jenkins, id: team/app/main}   # folder / multibranch path
requirements:
  - id: SAST
    tool: semgrep
    job_name: Scan                 # a stage; nested stages: "Scans / sast-go" or just "sast-go"
    report_path: reports/semgrep.json   # archiveArtifacts path
```

A stage is a "job". Nested, parallel and matrix stages are named by their path, e.g.
`Scan / Matrix - LANG = 'go' / sast`; `job_name: sast` then means *every* matrix instance.
Archived artifacts belong to the build, so `artifact_name` is not used. `same_commit` uses the
build's git checkout; jobs without SCM need `same_commit: false`.

## What ScanProof detects (live results)

| Pipeline | Jenkins shows | ScanProof |
|---|---|---|
| `catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE')` | build SUCCESS, stage failed | BLOCKED `FAILURE_MASKED_BY_ALLOW_FAILURE` |
| `warnError` / `unstable` | build and stage UNSTABLE | BLOCKED `FAILURE_MASKED_BY_ALLOW_FAILURE` |
| scripted `try { sh '...' } catch` | stage SUCCESS; only the step node failed | BLOCKED (`... failed and was caught (try/catch)`) |
| `retry(2)` that succeeds on the 2nd try | a failed step node, then the same step succeeds | VERIFIED (a retry, not a mask) |
| stage skipped by `when` | NOT_EXECUTED | BLOCKED `JOB_NOT_SUCCESS` |
| failed branch of `parallel` / one `matrix` instance | build SUCCESS | BLOCKED for that branch / instance |
| step nodes unreadable (plugin missing, no permission) | | INDETERMINATE (masking unknown) |
