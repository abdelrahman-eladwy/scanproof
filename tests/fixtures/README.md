# Test fixtures

| Folder | Source |
|---|---|
| `gitlab/` | Hand-written from GitLab REST API v4 docs. Replace with sanitized real responses from the demo project (`examples/gitlab-ci/`). |
| `semgrep/` | **Real** output of Semgrep 1.181.1 (`p/default`), produced by `.github/workflows/fixtures.yml`. |
| `trivy/` | **Real** output of Trivy 0.76.1. `trivy-python.json` was trimmed with `scripts/trim_trivy_report.py` (package list removed, 10 vulns per result kept; original counts recorded under `_scanproof_fixture`). |

## Regenerating scanner fixtures

1. Push any commit to a branch named `fixtures/scanners/<something>`; the `fixtures` workflow runs and
   commits its outputs to that branch under `generated-fixtures/`.
2. Review the files, trim large Trivy reports, copy them here, and update the versions above
   and the expected values in `tests/unit/test_scanners.py`.
3. Delete the branch. (Real GitLab API fixtures: same flow with `fixtures/gitlab/<something>`.)
