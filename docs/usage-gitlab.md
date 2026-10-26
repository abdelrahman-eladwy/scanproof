# Using ScanProof with GitLab

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

Start from [`examples/policies/scanproof.yaml`](../examples/policies/scanproof.yaml) and check it
locally with `scanproof validate -P policy.yaml`. Keep the policy file under CODEOWNERS review: a
policy the application team can edit is a policy they can weaken.

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

## Reading the report

`report.json` contains the decision, every check with its code and message, and the normalized
evidence (report SHA-256, scanner version, scope, image digest) for each requirement. Keep it as
a job artifact: it is the audit record of why a release was allowed or blocked.
