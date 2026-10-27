## What and why

<!-- One change per PR. Link the issue: "Closes #123". -->

## Checklist

- [ ] `ruff check . && ruff format --check . && pytest` passes locally
- [ ] Tests cover the change (real, sanitized fixtures for new report or API formats)
- [ ] The [security rules](https://github.com/abdelrahman-eladwy/scanproof/blob/main/CONTRIBUTING.md#security-rules-for-code-changes) still hold, in particular: unknown is never pass
- [ ] No new dependency, or the reason is stated above
- [ ] User-visible changes are noted in `CHANGELOG.md`
