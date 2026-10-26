# Scanner compatibility

Versions ScanProof's adapters are tested against (real reports in `tests/fixtures/`).

| Tool | Tested version | Format | Notes |
|---|---|---|---|
| Semgrep | 1.181.1 | `semgrep scan --json` | `paths.scanned` required for scope checks; `errors[]` levels `error`/`warn` |
| Trivy | 0.76.1 | `trivy image --format json`, SchemaVersion 2 | No error section in JSON, so scanner errors are reported as unknown |
| GitLab SAST (`gitlab-sast`) | security-products/semgrep:6 (6.30.0, Semgrep 1.181.0), report schema 15.2.4 | `gl-sast-report.json` | `scan.status` + warn/fatal messages = scanner errors. No scanned-file list, so scope checks are unknown |
| GitLab Container Scanning (`gitlab-container-scanning`) | security-products/container-scanning:8 (8.6.35, Trivy 0.72.0), schema 15.1.1 | `gl-container-scanning-report.json` | Image recorded as given; digest known only when scanned by digest and at least one finding exists |

| SARIF 2.1.0 (`sarif`) | Semgrep 1.181.1, Trivy 0.76.1, gitleaks 8.30.1, Checkov 3.3.30 | any SARIF 2.x log | Engine = `runs[].tool.driver.name`; errors only when the producer writes `invocations` (Semgrep does; Trivy, gitleaks, Checkov don't, so errors are unknown); scope only when it lists `artifacts`; result level falls back to the rule default. gitleaks reports its SARIF version as `v8.0.0` regardless of release |
| CycloneDX JSON (`cyclonedx`) | Trivy 0.76.1, Syft 1.55.0 (spec 1.7) | SBOM | Components counted recursively. Digest from `metadata.component` purl / bom-ref (Trivy has it, Syft doesn't). An empty `vulnerabilities: []` is treated as unknown, not zero: Trivy writes it without scanning |

Other versions likely work; unknown extra fields are ignored. Unsupported Trivy schema versions are
rejected as unparseable rather than guessed at.
