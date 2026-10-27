# Using ScanProof with Azure DevOps Pipelines

Built against real builds of public projects (`dnceng-public/public`, `azure-sdk/public`).

## Access

```bash
export AZURE_DEVOPS_TOKEN=...      # PAT with Build (Read); sent as Basic, only to the API origin
scanproof verify -P policy.yaml --pipeline "$(Build.BuildId)"
```

Inside a pipeline, map `$(System.AccessToken)` to `AZURE_DEVOPS_TOKEN` and pass
`--auth-scheme bearer`. Azure DevOps Server: `--url https://server/tfs` with project
`<collection>/<project>`.

## Policy

```yaml
project: {provider: azure-devops, id: my-org/my-project}
requirements:
  - id: SAST
    tool: semgrep
    job_name: SAST              # or "Build / SAST" (<stage> / <job>)
    artifact_name: semgrep      # PublishBuildArtifacts artifactName
    report_path: semgrep.json   # path inside the artifact
```

## What ScanProof detects

| Situation | What the API shows (real data) | ScanProof |
|---|---|---|
| Task fails under `continueOnError: true` | task and job `succeededWithIssues`, build `partiallySucceeded` | BLOCKED `FAILURE_MASKED_BY_ALLOW_FAILURE` (names the tasks) |
| Report artifact published by a different job | the artifact's `source` is that job's record | BLOCKED `REPORT_MISSING` ("published by another job") |
| Artifact from a failed earlier attempt of a re-run job | `source` is the old attempt's record | not accepted for the latest attempt |
| Re-run jobs | latest attempt in the timeline, earlier ones in `previousAttempts` | latest judged, attempts counted |
| Sign-in page instead of JSON (HTTP 203) | | INDETERMINATE (auth) |

Tasks that only log warnings can also end `succeededWithIssues`; ScanProof treats a scan job with
issues as not cleanly successful.

**Limitation: Pipeline Artifacts.** `PublishBuildArtifacts` artifacts are served by
`dev.azure.com` itself. `PublishPipelineArtifact` artifacts redirect to
`*.artifacts.visualstudio.com` without a signed URL; ScanProof sends the token only to the API
origin, so for a private project such a report is INDETERMINATE with that explanation. Publish
scan reports with `PublishBuildArtifacts`.
