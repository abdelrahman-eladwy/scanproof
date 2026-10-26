# Demo GitLab project

Used for real-world testing of ScanProof (milestone 1 onwards).

## Setup (once)

1. Create a new **private** project on gitlab.com (or your own GitLab), e.g. `scanproof-demo`.
2. Copy `.gitlab-ci.yml` and `sample-app/` from this folder into it and push.
3. Create a **project access token**: Settings > Access tokens, role *Reporter*,
   scope **`read_api` only**, expiry 30–90 days.
4. Locally: `export GITLAB_TOKEN=<token>` (don't paste it into chats, issues or commits).

## Produce test pipelines

Run one pipeline per scenario (Build > Pipelines > Run pipeline, add variable `SCENARIO`):
happy path (no variable), `no_sast`, `sast_allowed_failure`, `no_report`, `broken_report`,
`trivy_wrong_image`. Retry `trivy-image` manually on one of them.

## Collect fixtures

```bash
scanproof inspect -p <group>/scanproof-demo --pipeline <id> -o inspection-<scenario>.json
```

Then download `semgrep.json` and `trivy.json` artifacts from the happy-path pipeline. These become
the real fixtures for milestone 2. They contain only the demo project's data, so they are safe to
commit, but review them first anyway.
