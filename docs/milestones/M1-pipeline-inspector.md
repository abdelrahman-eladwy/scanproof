# M1 — GitLab Pipeline Inspector ✅ (implemented, pending real-pipeline validation)

**Goal:** `scanproof inspect` produces a judgement-free JSON inventory of a GitLab pipeline.

## Acceptance criteria

- [x] Fetch pipeline metadata (id, sha, ref, status) by numeric id or `group/project` path
- [x] Fetch all jobs with pagination (`x-next-page`) and `include_retried=true`
- [x] Collapse retries: latest attempt is effective; keep attempt history
- [x] Record `allow_failure`, commit SHA binding, artifact list per job
- [x] Map 401/403 -> AUTH, 404 -> NOT_FOUND, network/5xx/429 -> retried then reported; exit 2
- [x] Unknown job status -> `unknown`, never `success`
- [x] Token via env var only, Bearer header, never in output, logs or `repr`
- [x] Credential-safe redirects, HTTPS-only, TLS always on, `--ca-bundle`
- [x] Artifact download helper with streaming size cap and path-traversal guard
- [x] Usage errors exit 3 (not 2)
- [ ] **Run against the demo project for every scenario in `examples/gitlab-ci/` and commit
      the sanitized inspection outputs as fixtures** ← needs the maintainer
