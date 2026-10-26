# M4 — Hardening and v0.1 release

## Acceptance criteria

- [x] Docker image builds in CI, runs as non-root (checked), `--version` and a real `evidence`
      run work inside it; base image pinned by digest
- [x] `docs/usage-gitlab.md`: protected gate job, pipeline execution policy, separate audit
      project, with copy-paste snippets and `examples/gitlab-ci/scanproof-gate.gitlab-ci.yml`
- [x] `SECURITY.md` with private disclosure (GitHub private vulnerability reporting)
- [x] Release workflow: tag `vX.Y.Z` -> version check -> tests -> wheel + sdist -> PyPI
      (trusted publishing) -> GHCR image -> SLSA provenance attestations -> GitHub release;
      no long-lived publishing tokens
- [x] All third-party actions pinned to commit SHAs; Dependabot for actions, pip and Docker
- [x] README "Why not just use…" reviewed against current GitLab docs
- [x] Write-up of the design decisions (`docs/design-decisions.md`)
- [ ] One-time PyPI / GitHub setup in `docs/releasing.md` ← maintainer
- [ ] Demo: real GitLab demo project run showing VERIFIED and BLOCKED ← maintainer
- [ ] Tag `v0.1.0` ← maintainer, after the two items above
