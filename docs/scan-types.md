# Scan types: what each format can prove

ScanProof can only verify what a report actually records. This table shows which checks each
`tool:` can satisfy. A check marked **—** will always be **UNKNOWN** for that format (which blocks
by default), so leave it out of the policy or choose a format that records it.

| `tool:` | Type | errors (`scanner_errors_allowed`) | file scope (`minimum_scanned_files`, `required_paths`) | other scope | target digest (`image_digest_must_match`) | engine (`expected_scanner`) |
|---|---|---|---|---|---|---|
| `semgrep` | SAST | ✓ `errors[]` | ✓ `paths.scanned` | | | ✓ |
| `trivy` (image) | Container | — | targets only | | ✓ RepoDigests | ✓ |
| `trivy` (fs / repo) | Dependency | — | ✓ lockfiles read | | | ✓ |
| `gitlab-sast` | SAST | ✓ `scan.status` + messages | — | | | ✓ |
| `gitlab-container-scanning` | Container | ✓ | — | | only if scanned by digest | ✓ |
| `gitlab-dependency-scanning` | Dependency | ✓ | — (schema 15 dropped `dependency_files`) | | | ✓ |
| `gitlab-secret-detection` | Secrets | ✓ | — | | | ✓ |
| `checkov` | IaC | ✓ parsing errors | — | ✓ `minimum_resources` | | ✓ |
| `fortify` *(experimental)* | SAST | ✓ `EngineData/Errors` | ✓ `Build/SourceFiles` | | | ✓ |
| `sonatype-iq` *(experimental)* | Dependency | — | — | ✓ `minimum_components` | | ✓ |
| `sarif` | any | only if producer writes `invocations` (Semgrep yes; Trivy, gitleaks, Checkov no) | only if producer writes `artifacts` | | Trivy image SARIF ✓ | ✓ (use it!) |
| `cyclonedx` | SBOM | — | — | ✓ `minimum_components` | Trivy ✓, Syft — | ✓ |
| `gitleaks` | Secrets | — | — (not reported) | | | ✓ |
| `grype` | Container / Dependency | — | — | | ✓ repoDigests | ✓ |
| `osv-scanner` | Dependency | — | — (lists only sources with vulnerabilities) | | | ✓ |
| `snyk` | Dependency / Container | — | ✓ target files | ✓ `minimum_components` (dependencyCount) | — | ✓ |
| `kubescape` | Kubernetes (IaC) | — | ✓ manifests | ✓ `minimum_resources` | | ✓ |
| `zap` | **DAST** | — | | ✓ `minimum_endpoints` (ZAP 2.16+) | ✓ `target_url_must_match` (sites) | ✓ |
| `nuclei` | **DAST** | — | | | ✓ `target_url_must_match` (only when there are findings) | ✓ |
| `bitbucket-code-insights` | as reported | — | — | | | ✓ reporter |

`job_success`, `same_commit` and `report_required` work for every type: they come from the CI
platform and the report's presence, not from the report contents.

`required_paths` entries match whole path segments: `src/main/java` is satisfied by
`src/main/java/App.java`, not by `src/main/javascript/app.js`; `package-lock.json` only by that
file. `./`, `\` and `..` are normalized first, and a scanned path that climbs out of the scan
root (`src/../../x`) never counts. An entry that names nothing (`""`, `.`, `./`, `../src`) or an
empty list is a policy error (exit 3), because it would make the check always pass or do nothing.

## Recommended checks per type

**SAST** — prove the code was actually analysed, not just that the job was green.
```yaml
tool: semgrep
checks: {scanner_errors_allowed: 0, minimum_scanned_files: 1, required_paths: ["src/"]}
```

**Dependency scanning** — prove the lockfile you ship was read. A scan that found no lockfile
reports zero vulnerabilities and looks perfect.
```yaml
tool: trivy            # `trivy fs --format json .`
checks: {required_paths: ["package-lock.json"]}
```

**Secrets** — there is no scope in any tested secrets format, so the strongest evidence is that the
analyzer ran on this commit and reported success.
```yaml
tool: gitlab-secret-detection
checks: {scanner_errors_allowed: 0}
```

**IaC** — prove resources were evaluated; Checkov silently skips files it can't parse.
```yaml
tool: checkov          # `checkov -d infra -o json`
checks: {scanner_errors_allowed: 0, minimum_resources: 1}
```

**Container** — bind the scan to the image you deploy.
```yaml
tool: trivy            # `trivy image --format json registry/app@sha256:...`
checks: {image_digest_must_match: ${RELEASE_IMAGE_DIGEST}}
```

**SBOM** — an SBOM exists for the released image and isn't empty.
```yaml
tool: cyclonedx
checks: {minimum_components: 1, image_digest_must_match: ${RELEASE_IMAGE_DIGEST}}
```

**Anything else exporting SARIF** (CodeQL, Snyk, Checkmarx, ...) — always pin the engine:
```yaml
tool: sarif
checks: {expected_scanner: CodeQL}
```

## DAST: bind the scan to the deployment

A DAST report is only evidence for the environment it hit. `target_url_must_match` takes the
URL being released (or `${ENV_VAR}`) and passes when a scanned target has the same scheme, host
and port, and a path at or below it (`https://app.example.com/shop` covers `/shop/cart`, not
`/shopping`). If the report does not say what it scanned, the check is UNKNOWN.

```yaml
  - id: DAST
    tool: zap
    job_name: dast
    report_path: zap.json            # zap-baseline.py -J zap.json
    checks:
      target_url_must_match: ${DEPLOY_URL}
      minimum_endpoints: 5           # the spider found and tested at least 5 endpoints
```

For Nuclei use `-je report.json`: it writes `[]` when nothing is found, while `-jsonl` writes an
empty file that ScanProof cannot tell from a scan that never ran. With no findings Nuclei does
not record its target, so pair it with ZAP when the target must be proven.

