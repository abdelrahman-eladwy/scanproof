# Test fixtures

| Folder | Source |
|---|---|
| `gitlab/` | Hand-written from GitLab REST API v4 docs (small, targeted cases). |
| `gitlab-real/` | **Real** gitlab.com API responses for public pipelines (`gitlab-org/security-products/analyzers/semgrep`, `gitlab-org/cli`), collected anonymously by `.github/workflows/gitlab-contract.yml`. Allow-listed fields only: no user, commit author or runner data. |
| `semgrep/` | **Real** output of Semgrep 1.181.1 (`p/default`), produced by `.github/workflows/fixtures.yml`. |
| `sarif/` | **Real** SARIF from Semgrep 1.181.1, Trivy 0.76.1, gitleaks 8.30.1 (secret randomly generated at run time and redacted) and Checkov 3.3.30. Large logs trimmed with `scripts/trim_report.py` (results capped, unused rules removed). |
| `cyclonedx/` | **Real** CycloneDX 1.7 SBOMs from Trivy 0.76.1 and Syft 1.55.0, trimmed to 30 components. |
| `trivy/` | **Real** output of Trivy 0.76.1. `trivy-python.json` was trimmed with `scripts/trim_trivy_report.py` (package list removed, 10 vulns per result kept; original counts recorded under `_scanproof_fixture`). |

## Regenerating scanner fixtures

1. Push any commit to a branch named `fixtures/scanners/<something>`; the `fixtures` workflow runs and
   commits its outputs to that branch under `generated-fixtures/`.
2. Review the files, trim large Trivy reports, copy them here, and update the versions above
   and the expected values in `tests/unit/test_scanners.py`.
3. Delete the branch. (Real GitLab API fixtures: same flow with `fixtures/gitlab/<something>`.)
