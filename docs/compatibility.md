# Scanner compatibility

Versions ScanProof's adapters are tested against (real reports in `tests/fixtures/`).

| Tool | Tested version | Format | Notes |
|---|---|---|---|
| Semgrep | 1.181.1 | `semgrep scan --json` | `paths.scanned` required for scope checks; `errors[]` levels `error`/`warn` |
| Trivy | 0.76.1 | `trivy image --format json`, SchemaVersion 2 | No error section in JSON, so scanner errors are reported as unknown |

Other versions likely work; unknown extra fields are ignored. Unsupported Trivy schema versions are
rejected as unparseable rather than guessed at.
