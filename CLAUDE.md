# CLAUDE.md — guidance for AI coding agents working on ScanProof

Read this before changing anything. The maintainer reviews every PR; your job is to make
review fast and the result trustworthy.

## What this project is

A CLI that verifies security-scan *evidence* in CI pipelines (GitLab first; Semgrep and
Trivy first). It judges whether scans ran and produced valid, bound evidence — never
whether the application is secure.

## Architecture (modular monolith — keep the boundaries)

```
connectors/   CI platform access (GitLab). Returns models from scanproof.models only.
scanners/     (M2) one adapter per tool: raw report bytes -> normalized evidence.
evidence/     (M2) unified evidence model.
policy/       (M3) YAML policy models + engine. Never imports connectors or raw scanner JSON.
reporting/    console (stderr) and JSON (stdout / file) output.
inspection.py M1 pipeline inventory, no judgement.
cli.py        Typer CLI. Thin: parse args, call core, map errors to exit codes.
```

Dependency direction: `cli -> (inspection | policy) -> evidence -> models`; connectors and
scanners are leaves. A new scanner or CI provider must not require changes to `policy/`.

## Non-negotiable rules

1. **Unknown is never pass.** Any missing data, API error, unrecognized status or unparseable
   field maps to UNKNOWN / INDETERMINATE. Never default to success.
2. **Credentials:** token only from env vars; sent as `Authorization: Bearer` only to the
   configured GitLab origin; never in URLs, logs, exceptions, `repr`, or test snapshots.
3. **TLS verification is always on.** Support `--ca-bundle`; never add a `--insecure` flag.
4. **Redirects:** keep the manual redirect handling in `connectors/gitlab.py`. No HTTPS->HTTP.
5. **Size limits** on every download. Stream; don't trust Content-Length alone.
6. **Read-only.** ScanProof never writes to the CI platform.
7. Exit codes are a public contract: 0 ok, 1 policy failure, 2 indeterminate, 3 usage.

## Workflow

- One issue = one branch = one PR. Issues in `docs/issues/` have acceptance criteria;
  satisfy all of them and say which test covers each.
- Tests first for parsers and the policy engine. Use `respx` to mock GitLab; put real
  (sanitized) reports in `tests/fixtures/`. No network in unit tests.
- Before opening a PR run: `ruff check . && ruff format --check . && pytest`.
- Don't add dependencies without stating why in the PR. Prefer stdlib.
- Don't touch: `LICENSE`, exit-code meanings, the security rules above — ask instead.

## Commands

```bash
pip install -e ".[dev]"
pytest
ruff check . && ruff format .
scanproof inspect -p <project> --pipeline <id>   # needs GITLAB_TOKEN
```
