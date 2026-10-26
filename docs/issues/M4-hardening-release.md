# M4 — Hardening and v0.1 release

## Acceptance criteria

- [ ] Docker image builds in CI, runs as non-root, `docker run scanproof --version` works
- [ ] `docs/usage-gitlab.md`: running ScanProof from a protected deploy job and from a separate
      audit project, with copy-paste `.gitlab-ci.yml` snippets
- [ ] `SECURITY.md` with private disclosure contact
- [ ] Demo: recorded terminal session against the demo project showing VERIFIED and BLOCKED
- [ ] Release workflow: tag `v0.1.0` -> build wheel + sdist -> PyPI (trusted publishing) ->
      GHCR image; no long-lived publishing tokens
- [ ] README "Why not just use…" section reviewed against current GitLab features
- [ ] Write-up post explaining the design decisions (operational vs trusted assurance,
      unknown-is-never-pass, where to run it)
