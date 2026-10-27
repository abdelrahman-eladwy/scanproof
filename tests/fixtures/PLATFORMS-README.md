# Real Azure DevOps, Jenkins and Bitbucket API responses

Collected by `.github/workflows/platforms-contract.yml` (run 40463320446) with
`scripts/collect_{azure_devops,jenkins,bitbucket}.py`. Only whitelisted fields are kept: no
people (requestedBy/For, creators, authors), avatars, logs or commit messages.

- `azure-real/` - anonymous reads of the public projects `dnceng-public/public` (dotnet) and
  `azure-sdk/public`: build, timeline (and `timeline-<id>.json` for earlier attempts of re-run
  jobs) and artifact listings. Builds: partially succeeded (tasks failed under continueOnError),
  succeeded, and one with a re-run job.
- `jenkins-real/` - a throwaway Jenkins 2.580.1 (`ci/jenkins/`) running one pipeline per masking
  pattern: `api/json`, Pipeline Graph View (`stages/tree`, `stages/allSteps`) and Stage View
  (`wfapi`) responses. The only user is the throwaway `scanproof` account.
- `bitbucket-real/` - anonymous reads of public Atlassian pipe repositories: pipelines, steps,
  and Code Insights reports with annotations (`report-<uuid>[-annotations].json`).
