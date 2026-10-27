# Contributing

Thanks for your interest. ScanProof is pre-alpha, so expect things to move.

## How to contribute

1. Open an issue before large changes so we can agree on the approach.
2. Fork, branch from `main`, and keep each PR focused on one change.
3. `pip install -e ".[dev]"`, then make sure these pass:

   ```bash
   ruff check . && ruff format --check . && pytest
   ```

4. New scanner adapters need a sanitized real report in `tests/fixtures/`, parser unit tests,
   coverage of malformed / empty / error-containing reports, and an entry in `SAMPLES` in
   `tests/unit/test_robustness.py` so the adapter is fuzzed.
5. Don't add dependencies without saying why in the PR. Prefer the standard library.

## Security rules for code changes

ScanProof is a security tool: a bug that reports VERIFIED for missing or bad evidence is a
vulnerability. Every change must keep these rules. PRs that weaken them are not accepted; open
an issue first if you think one should change.

1. **Unknown is never pass.** Missing data, API errors, unrecognized statuses and unparseable
   fields map to UNKNOWN / INDETERMINATE, never to success.
2. **Credentials** come only from environment variables. They are sent in the `Authorization`
   header (Bearer, or Basic where the platform requires it) only to the configured API origin,
   and never appear in URLs, logs, exceptions, `repr` or test snapshots.
3. **TLS verification is always on.** Private CAs go through `--ca-bundle`; there is no
   `--insecure`.
4. **Redirects** are handled manually in `connectors/http.py`. HTTPS to HTTP is refused.
5. **Every download is size-limited** and streamed; `Content-Length` alone is not trusted.
6. **Read-only:** ScanProof never writes to the CI platform.
7. **Exit codes are a public contract:** 0 verified, 1 blocked, 2 indeterminate, 3 usage error.

The same rules are given to AI coding agents in [`CLAUDE.md`](CLAUDE.md); keep both in sync.

## Repository layout

| Path | Contents |
|---|---|
| `src/scanproof/` | The CLI and library (architecture overview in [`CLAUDE.md`](CLAUDE.md#architecture-modular-monolith--keep-the-boundaries)) |
| `tests/unit/` | Offline unit tests (no network) |
| `tests/fixtures/` | Real, sanitized scanner reports and CI API responses ([provenance](tests/fixtures/README.md)) |
| `scripts/` | Helpers that trim large real reports before they become fixtures |
| `examples/` | Policies and CI snippets for users ([index](examples/README.md)) |
| `docs/` | User and maintainer documentation ([index](docs/README.md)) |

Live end-to-end tests against real CI platforms and scanners live in a separate repository,
[scanproof-e2e](https://github.com/abdelrahman-eladwy/scanproof-e2e). They install ScanProof
from `main`, so they need no changes here; run one against your branch with **Run workflow**
and its `scanproof_ref` input.

## Security issues

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md), not in public
issues.
