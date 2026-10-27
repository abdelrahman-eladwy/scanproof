## Opt-in scanner-reported scope assurance

A parseable report is **not proof** that a scanner examined any files or targets.
Existing `v1alpha1` policies default to `assurance.minimum_level: report` for
backward compatibility. For a release gate that must see the scanner's own claim of
nonempty scan scope, opt in:

```yaml
apiVersion: scanproof.dev/v1alpha1
kind: PipelineAssurancePolicy
project: {provider: gitlab, id: group/app}
assurance:
  minimum_level: reported_scope
requirements:
  - id: SAST
    tool: semgrep
    job_name: semgrep-sast
    report_path: semgrep.json
    checks: {scanner_errors_allowed: 0}
  - id: IMAGE
    tool: trivy
    job_name: trivy-image
    report_path: trivy.json
enforcement:
  on_unknown: block
  on_nothing_applicable: block
```

This profile adds a `reported_scope` check to **every applicable job instance**.
It rejects a missing results section, an explicitly empty scope, or invalid
scanned-target entries; when scope cannot be determined it reports `UNKNOWN`
and blocks by default. A report with *zero vulnerabilities* and a nonempty
scanned scope can still pass. To avoid accidental fail-open release policies,
`reported_scope` rejects `on_unknown: warn`, `on_nothing_applicable: allow`,
or an optional report.

**Limit of the guarantee:** these values are assertions made by the scanner
report itself. ScanProof cannot independently prove that scanner execution
completed, that every relevant file was scanned, or that the CI workflow
could not forge its own report. Where relevant, combine this level with
`required_paths`, `minimum_scanned_files`, `image_digest_must_match`,
protected policies and signed attestations. An explicit policy waiver can
still override a failed check and is shown in the audit output.

Legacy `minimum_level: report` policies keep their current behavior.
Migration is opt-in; update policy files after verifying that your selected
scanner adapter emits meaningful scanned paths or scope counts.

---

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
