# Examples

| Path | What it is |
|---|---|
| [`policies/`](policies/) | Policies to start from, one per use case (see below). |
| [`release.yaml`](release.yaml) | One release built from several pipelines (`scanproof verify-release`, see [advanced policy](../docs/advanced-policy.md#one-release-several-pipelines)). |
| [`gitlab-ci/`](gitlab-ci/) | A demo GitLab project and a copy-paste release gate job. |
| [`demo/`](demo/) | Policies for the [two-pipeline demo](../docs/demo.md). |
| [`sample-projects/`](sample-projects/) | Deliberately vulnerable inputs used to generate real scanner fixtures. Never deploy them. |

## Policies

| Policy | Use it when |
|---|---|
| [`scanproof.yaml`](policies/scanproof.yaml) | GitLab CI with Semgrep and Trivy, image digest bound to the release |
| [`gitlab-templates.yaml`](policies/gitlab-templates.yaml) | GitLab's own SAST and Container Scanning CI templates |
| [`sarif-and-sbom.yaml`](policies/sarif-and-sbom.yaml) | Any SARIF-producing scanner, plus an SBOM bound to the shipped image |
| [`attested-release.yaml`](policies/attested-release.yaml) | GitHub Actions with Sigstore-signed evidence ([attestations](../docs/attestations.md)) |
| [`dast.yaml`](policies/dast.yaml) | DAST evidence bound to the deployment being released |
| [`fortify.yaml`](policies/fortify.yaml) | Fortify SCA results (experimental) |

Check any policy before use: `scanproof validate -P <policy>`.
