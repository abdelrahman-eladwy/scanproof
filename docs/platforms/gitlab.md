# Using ScanProof with GitLab

> **Before v0.1.0 is released** there is no PyPI package or container image yet. Until then install
> from source with `pip install "git+https://github.com/abdelrahman-eladwy/scanproof"` and build the
> image yourself with `docker build -t scanproof .` from a checkout.

## 1. Create a read-only token

Project or group access token, role **Developer**, scope **`read_api`** only, with an expiry.

Why Developer: since GitLab 17.0, artifacts produced by GitLab's security scanning templates are
restricted to the Developer role, so a Reporter token gets HTTP 403 on the reports and every
requirement ends INDETERMINATE. The `read_api` scope still makes the token read-only through
the API. If your scans upload plain `artifacts:paths` with no `access:` restriction, Reporter is
enough.
Store it as a **masked, protected** CI/CD variable, e.g. `SCANPROOF_GITLAB_TOKEN`, and pass
`--token-env SCANPROOF_GITLAB_TOKEN`. ScanProof never accepts tokens as arguments.

## 2. Write a policy

Start from [`examples/policies/scanproof.yaml`](../../examples/policies/scanproof.yaml) and check it
locally with `scanproof validate -P policy.yaml`. Keep the policy file under CODEOWNERS review: a
policy the application team can edit is a policy they can weaken.

### Using GitLab's own SAST / Container Scanning templates?

Use the `gitlab-sast` and `gitlab-container-scanning` tools, which read GitLab's security report
format. Start from [`examples/policies/gitlab-templates.yaml`](../../examples/policies/gitlab-templates.yaml).
That format has no list of scanned files, so scope checks are not available, and the container
report only carries a digest if you scan by digest:

```yaml
container_scanning:
  variables:
    CS_IMAGE: "$CI_REGISTRY_IMAGE@$RELEASE_IMAGE_DIGEST"
```

## 3. Bind the container scan to the image you ship

The build job knows the digest it pushed. Hand it to later jobs with a dotenv report:

```yaml
build-image:
  stage: build
  script:
    - docker build -t "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" .
    - docker push "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
    - echo "RELEASE_IMAGE_DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" | cut -d@ -f2)" > build.env
  artifacts:
    reports:
      dotenv: build.env

trivy-image:
  stage: security
  needs: [build-image]
  script:
    - trivy image --format json --output trivy.json "$CI_REGISTRY_IMAGE@$RELEASE_IMAGE_DIGEST"
  artifacts: {when: always, paths: [trivy.json]}
```

and in the policy: `image_digest_must_match: ${RELEASE_IMAGE_DIGEST}`. Scanning by tag is not
enough: a tag can point to a different image than the one you deploy.

## 4. Choose where the gate runs

Who can edit the job that runs ScanProof decides how much the result is worth.

| Option | Strength | GitLab tier |
|---|---|---|
| **A. Gate job in the app pipeline** (template included from a protected project) | Catches mistakes and drift: skipped, failed, masked or empty scans. Does **not** stop a developer who edits `.gitlab-ci.yml` to remove the gate. | Any |
| **B. Gate injected by a group-level pipeline execution policy** | The gate is enforced from outside the project's `.gitlab-ci.yml`. How hard it is to bypass depends on your role setup: restrict who can create project-level policies. | Ultimate |
| **C. Separate audit project** (triggered or scheduled, own token) | Independent record of every release pipeline, even when A is bypassed. Use with A, or alone for audits. | Any |

### Option A: gate job before deploy

```yaml
include:
  - project: my-group/security-templates
    ref: v1
    file: scanproof-gate.gitlab-ci.yml

stages: [build, security, verify, deploy]

scanproof:
  extends: .scanproof-verify
  needs: [build-image, semgrep-sast, trivy-image]   # wait for the scans, receive the digest
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

deploy-prod:
  stage: deploy
  needs: [scanproof]                                 # deploy only after VERIFIED (exit 0)
  environment: production
  script: ./deploy.sh
```

Exit codes: `0` VERIFIED, `1` BLOCKED, `2` INDETERMINATE (e.g. token lacks access), `3` bad
policy or arguments. Any non-zero fails the job, so `deploy-prod` never starts.

### Option C: audit project

In a separate project the application team cannot push to:

```yaml
audit:
  image: {name: "ghcr.io/abdelrahman-eladwy/scanproof:0.1", entrypoint: [""]}
  rules:
    - if: $UPSTREAM_PIPELINE_ID
  script:
    - scanproof verify -P policies/$UPSTREAM_PROJECT_SLUG.yaml
        -p "$UPSTREAM_PROJECT_ID" --pipeline "$UPSTREAM_PIPELINE_ID"
        --gitlab-url "$CI_SERVER_URL" --token-env AUDIT_TOKEN -o report.json
  artifacts: {when: always, paths: [report.json], expire_in: 1 year}
```

Trigger it from the app pipeline with a `trigger:` job (passing the three `UPSTREAM_*` variables)
and `strategy: depend` if deploys should wait for it.

## Parallel, matrix and child-pipeline jobs

`job_name` matches the job you wrote in `.gitlab-ci.yml`, wherever GitLab put its instances:

| Pipeline shape | Job names GitLab reports | `job_name: semgrep` matches |
|---|---|---|
| `parallel: 3` | `semgrep 1/3`, `semgrep 2/3`, `semgrep 3/3` | all three; a missing index (e.g. no `2/3`) is a FAIL |
| `parallel: matrix:` | `semgrep: [python]`, `semgrep: [go]` | every matrix instance; a removed one is a FAIL only with `instances: [python, go]` |
| child pipeline (`trigger: include:`) | `semgrep` in the child | `<trigger job> > semgrep` |
| multi-project (`trigger: project:`) | `semgrep` in the other project | same, artifacts read from that project |

When several instances match, **every one must pass**; each check is reported per instance
(`job_success [semgrep 2/3]`). A job named exactly like `job_name` counts as one more
instance; it does **not** stand in for the others. A passing `semgrep` next to a failing
`semgrep 1/2` or `trigger > semgrep` is BLOCKED
([#59](https://github.com/abdelrahman-eladwy/scanproof/issues/59)). If a same-named job really
is unrelated, rename it. To pin one child job, name it fully:
`job_name: "security-child > semgrep"`. A qualified name matches only that job, not its
parallel or matrix instances ([#62](https://github.com/abdelrahman-eladwy/scanproof/issues/62)).

Matrix names carry no total, so a leg dropped from `parallel: matrix:` is invisible unless the
requirement declares its legs: `instances: [python, go]` makes a missing `semgrep: [go]` a FAIL
(`REQUIRED_INSTANCE_ABSENT`). Multi-variable legs are labelled as GitLab names them,
`semgrep: [python, 3.12]` → `"python, 3.12"`. `assurance.profile: production` requires the
declaration whenever matrix legs are matched
([#60](https://github.com/abdelrahman-eladwy/scanproof/issues/60),
[details](../advanced-policy.md#matrix-legs-declare-the-instances-that-must-run)).

Downstream copies have no total either: if two child pipelines run `semgrep` and the
`svc-b` trigger is deleted, `svc-a > semgrep` still passes. Declare the pipelines that must run
it, `copies: [svc-a, svc-b]` (`""` for the parent's own job): a missing one is a FAIL
(`REQUIRED_COPY_ABSENT`), and `production` requires the declaration whenever a downstream copy
is matched ([#65](https://github.com/abdelrahman-eladwy/scanproof/issues/65), [details](../advanced-policy.md#prefixed-copies-declare-the-copies-that-must-run)).

ScanProof follows downstream pipelines up to 3 levels and 50 pipelines. If a downstream pipeline
can't be read (the token has no access to that project) and the required job isn't found
elsewhere, the result is INDETERMINATE (`JOB_MAYBE_IN_UNREADABLE_PIPELINE`), not "job absent". The same holds
while a trigger hasn't started its pipeline yet. Exactly when a missing job counts as proven
absent: [Missing or unreadable](../advanced-policy.md#missing-or-unreadable-when-absence-is-proven).
Multi-project pipelines usually run on **another repository's commit**, so `same_commit` fails
there unless you set `same_commit: false` for that requirement on purpose.

If the gate runs while a scan job is still running, a missing report is UNKNOWN
(`REPORT_NOT_YET_AVAILABLE`), not FAIL: run the gate after the scans with `needs:`.

## Reading the report

`report.json` contains the decision, every check with its code and message, and the normalized
evidence (report SHA-256, scanner version, scope, image digest) for each requirement. Keep it as
a job artifact: it is the audit record of why a release was allowed or blocked.
