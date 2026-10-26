# Sample projects

Deliberately vulnerable inputs used by `.github/workflows/fixtures.yml` to produce real scanner
reports for tests. Never deploy or apply them.

| Folder | Scanned by |
|---|---|
| `terraform/` | Checkov (IaC) |
| `node/` | Trivy filesystem, GitLab dependency scanning (lodash 4.17.15 has known CVEs) |

Secret-detection fixtures are produced from a **randomly generated fake token at workflow run
time**, with scanner redaction on, so no secret-looking string is ever committed.
