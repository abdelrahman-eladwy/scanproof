# Advanced policy: waivers, freshness, shared targets, releases

## Waivers (accepted risk, with an expiry date)

A waiver turns one failing (or unknown) check of one requirement into `WAIVED` until a date.
`WAIVED` counts as passing, is shown in the report with its reason and approver, and the
report warns when a waiver is applied, has expired, has not started yet, or matched nothing.

```yaml
waivers:
  - requirement: SAST
    check: scanner_errors          # covers its instances too: "scanner_errors [sast 2/3]"
    code: SCANNER_ERRORS           # optional: only this result code
    reason: "Semgrep parser bug on vendored code, tracked in SEC-123"
    approved_by: security-team
    created: 2026-10-27
    expires: 2026-11-30            # last day it applies (UTC); after that it does nothing
enforcement:
  max_waiver_days: 60              # optional: refuse waivers longer than this (needs `created`)
```

A waiver only ever touches the check it names, and only when that check failed or is unknown.
It cannot make a requirement that does not apply (`applies_to`) count as verified.

## Scan freshness

```yaml
checks:
  max_age_hours: 24   # the scan job finished at most 24 h before verification
```

Age is measured from the CI platform's own finish time for the job (not a timestamp inside the
report, which the job controls). No finish time (e.g. a job still running) is UNKNOWN. Use it
when an old pipeline's evidence could be replayed for a new deployment.

## Same target across requirements

```yaml
requirements:
  - id: CONTAINER
    tool: trivy
    ...
  - id: SBOM
    tool: cyclonedx
    checks:
      same_target_as: CONTAINER    # the SBOM describes the image that was scanned
```

Both reports must name the same image (repo digest or image ID) or, for DAST, the same origin.
Found with real data: `python:3.12-slim` scanned by Trivy one day and Grype the next were
different images (the tag moved), so the check fails although both reports say
`python:3.12-slim`. A report that names no digest (e.g. a Syft SBOM) makes it UNKNOWN.

## One release, several pipelines

`scanproof verify-release -R release.yaml` verifies each component with its own policy and
pipeline, on any platform, and gives one decision: VERIFIED only if all are, BLOCKED if any is,
INDETERMINATE otherwise.

```yaml
apiVersion: scanproof.dev/v1alpha1
kind: ReleaseAssurance
metadata: {name: shop-2.3}
components:
  - {name: backend,  policy: policies/backend.yaml,  pipeline: 1042}          # GitLab
  - {name: frontend, policy: policies/frontend.yaml, pipeline: "${FRONTEND_RUN_ID}"}  # GitHub
  - {name: chart,    policy: policies/chart.yaml,    pipeline: 57, url: https://ci.example.com}  # Jenkins
```

Policy paths are relative to the release file. Each component's token comes from its
provider's usual env var (`GITLAB_TOKEN`, `GITHUB_TOKEN`, `JENKINS_USER`/`JENKINS_TOKEN`, ...).
The JSON report (`-o`) holds every component's full verification report.
