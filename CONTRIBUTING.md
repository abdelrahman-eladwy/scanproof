# Contributing

Thanks for your interest. ScanProof is pre-alpha, so expect things to move.

1. Open an issue before large changes so we can agree on the approach.
2. Fork, branch from `main`, and keep PRs focused on one change.
3. `pip install -e ".[dev]"`, then make sure `ruff check .`, `ruff format --check .` and
   `pytest` all pass.
4. New scanner adapters need: a sanitized real report in `tests/fixtures/`, parser unit tests,
   and coverage of malformed / empty / error-containing reports.
5. Read the security rules in [`CLAUDE.md`](CLAUDE.md#non-negotiable-rules); they apply to
   humans too.

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
[scanproof-e2e](https://github.com/abdelrahman-eladwy/scanproof-e2e). They install ScanProof from `main`, so they need no changes here; run one
against your branch with **Run workflow** and its `scanproof_ref` input.

## Security issues

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md), not in public
issues.
