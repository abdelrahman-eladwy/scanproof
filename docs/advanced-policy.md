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

`applies_to` needs the pipeline's ref. When the provider reports none (a Jenkins build without
Git `BuildData`, for example), a scoped requirement is `UNKNOWN` (`REF_UNKNOWN`), not
"not applicable": an unknown ref cannot prove a requirement is out of scope, and
`on_nothing_applicable: allow` does not apply to it. Only patterns that match every ref (`*`)
are evaluated without one.

## Scan freshness

```yaml
checks:
  max_age_hours: 24   # the scan job finished at most 24 h before verification
```

Age is measured from the CI platform's own finish time for the job (not a timestamp inside the
report, which the job controls). No finish time (e.g. a job still running) is UNKNOWN.
A finish time more than five minutes **in the future** is also UNKNOWN: an implausible
timestamp is not evidence of freshness. Up to five minutes of positive clock skew is
tolerated and explicitly described in the check result. Use this check when an old
pipeline's evidence could be replayed for a new deployment.

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

## Matrix legs: declare the instances that must run

`job_name` covers every matrix leg of the job, and every leg must pass. But matrix leg names
carry no total: GitLab names a `parallel: matrix:` leg `sast: [py]` and GitHub a
`strategy.matrix` leg `sast (py)`. If someone drops `js` from the matrix, the remaining legs
pass and nothing in the pipeline shows that a leg is gone. (`parallel: N` names, `sast 2/3`,
do carry the total; a missing index is already a FAIL.)

Declare the legs the requirement needs:

```yaml
requirements:
  - id: SAST
    tool: semgrep
    job_name: sast
    report_path: semgrep.json
    instances: [py, js]            # GitLab 'sast: [py]', GitHub 'sast (py)'
```

- A declared label with no leg is a FAIL, `REQUIRED_INSTANCE_ABSENT` on
  `job_present [sast: [js]]` (GitHub: `job_present [sast (js)]`). If the job runs with no
  matrix at all, every declared label is missing.
- A leg built from several matrix variables is labelled by its values joined with `, `, as
  the platform names it: `instances: ["py, 3.12"]` for `sast: [py, 3.12]` / `sast (py, 3.12)`.
  Quote labels that YAML would read as a number or boolean (`"3.12"`, `"on"`).
- Extra, undeclared legs are allowed. They are still evaluated and must pass.
- Labels are checked in each pipeline that runs the matrix: with downstream or
  reusable-workflow copies (`trigger > sast: [py]`, `caller / sast (py)`), each copy that runs
  any leg must run every declared leg.
- Without `instances`, behavior is unchanged: the legs that ran are evaluated, a removed leg is
  not detected, and `verify` adds a warning saying so.

Copies told apart only by a prefix carry no label; declare them with
[`copies`](#prefixed-copies-declare-the-copies-that-must-run).

## Prefixed copies: declare the copies that must run

`job_name: sast` also matches copies of the job that differ only by a prefix: several
downstream pipelines (`svc-a > sast`, `svc-b > sast`), several callers of a reusable workflow
(`api / sast`, `web / sast`) and Jenkins matrix stages (`Scan / Matrix - LANG = 'go' / sast`).
Like matrix legs, these names carry no total: if someone deletes the `svc-b` trigger job, the
`web` caller or the `go` axis value, the remaining copies pass and nothing shows a copy is gone
([#65](https://github.com/abdelrahman-eladwy/scanproof/issues/65)).

Declare the copies the requirement needs, by the path in front of the job name, without the
trailing separator:

```yaml
requirements:
  - id: SAST
    tool: semgrep
    job_name: sast
    report_path: semgrep.json
    copies: ["", svc-a, svc-b]     # "" = the pipeline's own 'sast'; then 'svc-a > sast', ...
```

- A declared copy with no job is a FAIL, `REQUIRED_COPY_ABSENT` on `job_present [svc-b > sast]`.
  If the missing copy may be in a downstream pipeline the token couldn't read, it is UNKNOWN
  (`JOB_MAYBE_IN_UNREADABLE_PIPELINE`) instead. Each copy is judged on its own, also when no
  copy ran at all: a provably absent copy is a FAIL even if another declared copy may be in an
  unreadable pipeline.
- Paths are written as the platform names them: `deploy > svc-a` for a nested GitLab child,
  `security` for GitHub's `security / sast`, `"Scan / Matrix - LANG = 'go'"` for Jenkins.
  `svc-a >` (trailing separator) is a load error.
- Extra, undeclared copies are allowed. They are still evaluated and must pass.
- With [`instances`](#matrix-legs-declare-the-instances-that-must-run) as well, every declared
  copy that ran must run every declared leg, even if it no longer runs as a matrix.
- Without `copies`, behavior is unchanged: the copies that ran are evaluated, a removed copy
  is not detected, and `verify` adds a warning saying so.
- A qualified `job_name` (`svc-a > sast`) matches only that job and needs no `copies`. One
  requirement per qualified name is an alternative when the copies need different checks.

## Missing or unreadable: when absence is proven

A required job, declared copy or declared matrix leg is **absent** (BLOCKED) only when the job
inventory ScanProof read is complete enough to prove it isn't there. When the inventory has a
gap that could hold it, the result is INDETERMINATE: ScanProof does not claim a scan is missing
when it only failed to look. Absence is about the *job inventory*; a job that exists but whose
report can't be fetched is judged per check (`evidence_error`, UNKNOWN), not as absent.

**1. The inventory.** The root pipeline's job list (every page, every retry; the latest attempt
counts), plus, on GitLab, every downstream pipeline reached through trigger (bridge) jobs,
breadth first, up to 3 levels and 50 pipelines. Downstream jobs are named
`<trigger> > <job>`. GitHub, Jenkins, Azure DevOps and Bitbucket have no downstream pipelines:
reusable-workflow callers (`caller / job`) and stage paths are all in the one run's job list.

**2. If the root can't be read**, nothing is decided. Any error reading the pipeline or its job
list (401/403/404, 429 or 5xx after retries, a timeout, an invalid payload, the page limit)
ends `verify` with exit 2 and, with `-o`, an error report (`decision: INDETERMINATE` and an
`error` object, no `requirements`).

**3. Each GitLab trigger** leaves its downstream pipeline in one of three states:

| Trigger and downstream pipeline | State | Why |
|---|---|---|
| Pipeline exists, its job list read | **read** | absence inside it is proven |
| Pipeline exists, job list can't be read (403 private project, 404, 5xx, invalid payload) | **unreadable** | the job may be there |
| A pipeline's trigger list can't be read (except a 404 at the root: no bridges API) | **unreadable** | its children are unknown |
| Beyond 3 levels or 50 pipelines | **unreadable** | not looked at |
| No pipeline yet; trigger `created`, `pending`, `waiting_for_resource`, `preparing`, `scheduled`, `running`, or a status ScanProof doesn't recognize | **unreadable** (`<trigger> (not started: <status>)`) | it may still start ([#68](https://github.com/abdelrahman-eladwy/scanproof/issues/68)) |
| No pipeline; trigger `failed`, `canceled`, `skipped`, `success`, or `manual` not played | **absent** (a warning) | no pipeline will hold its jobs without someone acting |

**4. The decision** for a job, copy or leg that is not in the inventory:

- nothing unreadable → BLOCKED: `REQUIRED_JOB_ABSENT`, `REQUIRED_COPY_ABSENT` or
  `REQUIRED_INSTANCE_ABSENT`;
- an unreadable pipeline could contain the required path → INDETERMINATE,
  `JOB_MAYBE_IN_UNREADABLE_PIPELINE`; the message lists the relevant pipelines and why.

A job that **was** found can still have unseen copies in an unreadable pipeline. Under
`production`, without `copies`, that is INDETERMINATE too (`COPIES_UNBOUNDED`, [#71](https://github.com/abdelrahman-eladwy/scanproof/issues/71),
[above](#matrix-legs-under-production)).

Matrix legs and `parallel: N` indices are the exception: they are only ever reported missing
inside a pipeline that was read and runs the same job, so they are always proven.

Uncertainty is scoped to downstream paths ([#69](https://github.com/abdelrahman-eladwy/scanproof/issues/69)).
An unreadable `svc-private` cannot hide a removed declared `svc-b`: that copy is BLOCKED.
An unreadable `deploy` can hide `deploy > svc-b`, so that path remains UNKNOWN. An unreadable
trigger inventory leaves its descendants unknown, and depth/count limits do too. Bare job
names without `copies` remain conservative because the job could be anywhere. A declared
root copy (`copies: [""]`) cannot be hidden inside a child. Rate limiting of a required
child's jobs still leaves its evidence UNKNOWN; an unrelated private child never substitutes
for a public child's missing evidence.

## Production profile: reject assurance-weakening settings

Every `v1alpha1` setting is valid and evaluated exactly as documented, but some of them let a
weaker pipeline reach VERIFIED. `assurance.profile: production` makes each of them a load
error (exit 3, before any CI platform is contacted). The default, `profile: compatible`,
accepts everything, as before profiles existed.

```yaml
assurance:
  profile: production
  minimum_level: reported_scope   # independent; recommended alongside production
```

`profile` changes which policies load, plus two verify-time rules that can't be decided at
load time (below, [matrix legs and prefixed copies](#matrix-legs-under-production)). Otherwise a policy with no
weakening settings loads under either profile and returns the same decision. Every shipped example in [`examples/policies/`](../examples/policies/) passes
`production`.

| Code | Setting | Why it weakens assurance |
|---|---|---|
| `ON_UNKNOWN_WARN` | `enforcement.on_unknown: warn` | evidence that can't be proven passes with a warning |
| `NOTHING_APPLICABLE_ALLOW` | `enforcement.on_nothing_applicable: allow` | VERIFIED when nothing was verified |
| `JOB_SUCCESS_DISABLED` | `checks.job_success: false` | a failed or cancelled scan job's report counts |
| `SAME_COMMIT_DISABLED` | `checks.same_commit: false` | evidence from another commit counts |
| `REPORT_OPTIONAL` | `checks.report_required: false` | a missing report is accepted |
| `REPORT_OPTIONAL_DROPS_CHECKS` | `report_required: false` plus evidence checks | with no report, `image_digest_must_match`, `minimum_scanned_files`, etc. silently don't run |
| `ALL_CHECKS_DISABLED` | a requirement with every check off | outcome is always NOT_APPLICABLE; it can never block |
| `ATTESTATION_SAME_COMMIT_DISABLED` | `attestation.same_commit: false` | signatures replayable across commits |
| `ATTESTATION_SAME_RUN_DISABLED` | `attestation.same_run: false` | signatures replayable across runs |
| `SIGNER_REPOSITORY_UNPINNED` | `signer.workflow` without `signer.repository` | a loose regex accepts any repository under the issuer |
| `WAIVER_UNBOUNDED` | waivers without `enforcement.max_waiver_days` | `expires` can be any date |
| `WAIVER_LIMIT_TOO_LONG` | `enforcement.max_waiver_days` above 90 | a huge limit makes waivers effectively permanent |
| `WAIVER_REMOVES_REQUIREMENT` | a waiver on `job_present` (any code, any instance) | accepts a pipeline without the required job |
| `WAIVER_HIDES_UNDECLARED_INSTANCES` | a waiver on `instances_declared` | accepts matrix legs whose removal can't be detected |
| `WAIVER_HIDES_UNDECLARED_COPIES` | a waiver on `copies_declared` | accepts prefixed copies whose removal can't be detected |
| `WAIVER_HIDES_UNBOUNDED_COPIES` | a waiver on `copies_bounded` | accepts copies in unreadable pipelines that were never judged |

### Matrix legs under production

Whether `job_name` runs as a matrix is only known from the pipeline, so this is checked by
`verify`, not at load time. Under `profile: production`, a requirement whose `job_name` matched
matrix legs (`sast: [py]`, `sast (py)`) but declares no [`instances`](#matrix-legs-declare-the-instances-that-must-run)
is UNKNOWN: check `instances_declared`, code `INSTANCES_UNDECLARED`, decision INDETERMINATE
(exit 2). A plain job, or `parallel: N` legs, need no declaration. Under `compatible` the same
situation is only a warning.

The same holds for [prefixed copies](#prefixed-copies-declare-the-copies-that-must-run): a
requirement whose bare `job_name` matched any prefixed copy (`svc-a > sast`, `api / sast`, a
Jenkins stage path) but declares no `copies` is UNKNOWN: check `copies_declared`, code
`COPIES_UNDECLARED`, exit 2 ([#65](https://github.com/abdelrahman-eladwy/scanproof/issues/65)). A job matched only by its exact, unprefixed name needs no
declaration. **Upgrading:** production policies for pipelines with downstream jobs, reusable
workflows or nested Jenkins stages must add `copies` (or use qualified job names).

Copies can also be **hidden**: a downstream pipeline that can't be read (or hasn't started)
may run the job too, and that copy must pass like the others. Under `profile: production`, a
requirement with an unqualified `job_name` and no `copies`, whose job was found while such a
pipeline exists, is UNKNOWN: check `copies_bounded`, code `COPIES_UNBOUNDED`, exit 2 ([#71](https://github.com/abdelrahman-eladwy/scanproof/issues/71)).
Declaring `copies` bounds the set: `copies: [""]` says only the pipeline's own job is required,
so a copy in the unreadable pipeline is not. A qualified `job_name` (`svc-a > sast`) can't
match a hidden copy and is unaffected. Under `compatible`, the visible copies decide, with a
warning.

All violations are listed at once. To see them for any policy, without changing its profile:

```console
$ scanproof validate --explain -P policy.yaml
OK: policy 'app-release' with 2 requirement(s): SAST, IMAGE
profile: compatible
minimum assurance: report (a parseable report is enough; reports are NOT required to claim they scanned anything; set assurance.minimum_level: reported_scope)
1 assurance-weakening opt-in(s), each rejected by assurance.profile: production:
  - SAME_COMMIT_DISABLED at requirements[SAST].checks.same_commit: evidence from a job that ran on another commit counts
  note INSTANCES_UNDECLARED at requirements[SAST, IMAGE].instances: no declared matrix legs: ...
```

`--explain` always states the policy's `minimum_level`. Under `report`, a policy with no
weakening opt-ins still does not require reports to claim they scanned anything, so the
output says so explicitly.

The 90-day ceiling is a policy choice, not a platform limit: long enough for a quarterly
remediation cycle, short enough that a waiver must be re-approved. It applies whether or
not the policy has waivers today.

`--explain` also prints **notes**, which the profile doesn't reject at load time:

- `GITLAB_SAME_RUN_IS_PIPELINE_WIDE`: GitLab's Fulcio identity names the pipeline, not the
  job, so any job in the verified pipeline can produce an accepted signature
  ([attestations](attestations.md)). No setting removes this; protect who can edit the
  pipeline.
- `INSTANCES_UNDECLARED`: lists the requirements without `instances`. If their job runs as a
  matrix, a removed leg can't be detected; under `production`, `verify` reports such legs as
  UNKNOWN ([above](#matrix-legs-under-production)). Declaring `instances` removes the note.
- `COPIES_UNDECLARED`: lists the requirements without `copies`. If their job runs as prefixed
  copies, a removed copy can't be detected; under `production`, `verify` reports such copies
  as UNKNOWN. Declaring `copies` removes the note.
