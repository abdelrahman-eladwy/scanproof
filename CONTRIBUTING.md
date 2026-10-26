# Contributing

Thanks for your interest. ScanProof is pre-alpha, so expect things to move.

1. Open an issue before large changes so we can agree on the approach.
2. Fork, branch from `main`, and keep PRs focused on one change.
3. `pip install -e ".[dev]"`, then make sure `ruff check .`, `ruff format --check .` and
   `pytest` all pass.
4. New scanner adapters need: a sanitized real report in `tests/fixtures/`, parser unit tests,
   and coverage of malformed / empty / error-containing reports.
5. Read the security rules in [`CLAUDE.md`](CLAUDE.md#non-negotiable-rules) — they apply to
   humans too.

Report security issues privately (see `SECURITY.md` once published), not in public issues.
