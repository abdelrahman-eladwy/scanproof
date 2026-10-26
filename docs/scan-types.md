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
| `sarif` | any | only if producer writes `invocations` (Semgrep yes; Trivy, gitleaks, Checkov no) | only if producer writes `artifacts` | | Trivy image SARIF ✓ | ✓ (use it!) |
| `cyclonedx` | SBOM | — | — | ✓ `minimum_components` | Trivy ✓, Syft — | ✓ |

`job_success`, `same_commit` and `report_required` work for every type: they come from the CI
platform and the report's presence, not from the report contents.

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
