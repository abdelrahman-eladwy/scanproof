# GitLab CI example

A small GitLab project for trying ScanProof end to end, plus a release gate you can copy.

| File | Purpose |
|---|---|
| [`scanproof-gate.gitlab-ci.yml`](scanproof-gate.gitlab-ci.yml) | Copy-paste release gate job. See [docs/platforms/gitlab.md](../../docs/platforms/gitlab.md). |
| [`.gitlab-ci.yml`](.gitlab-ci.yml) | Demo pipeline (Semgrep + Trivy) that can reproduce each failure mode ScanProof detects. |
| `sample-app/` | Deliberately vulnerable demo code scanned by the pipeline. Never deploy it. |

Policy for this project: [`examples/policies/scanproof.yaml`](../policies/scanproof.yaml).

## Try it

1. Create a new **private** project on gitlab.com (or your own GitLab), e.g. `scanproof-demo`.
2. Copy `.gitlab-ci.yml` and `sample-app/` into it and push.
3. Create a **project access token**: Settings > Access tokens, role *Developer*, scope
   **`read_api` only**, expiry 30–90 days. Export it as `GITLAB_TOKEN` (never paste it into chats,
   issues or commits).
4. Run one pipeline per scenario (Build > Pipelines > Run pipeline, variable `SCENARIO`):
   happy path (no variable), `no_sast`, `sast_allowed_failure`, `no_report`, `broken_report`,
   `trivy_wrong_image`. For a retried job, retry `trivy-image` manually.
5. Verify each one:

   ```bash
   export RELEASE_IMAGE_DIGEST=sha256:...   # the image the pipeline released
   scanproof verify -P examples/policies/scanproof.yaml -p <group>/scanproof-demo --pipeline <id>
   ```

   The happy path is VERIFIED (exit 0); every other scenario is BLOCKED or INDETERMINATE.
