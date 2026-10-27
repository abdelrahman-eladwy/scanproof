# ScanProof documentation

New here? Start with the [project README](../README.md), then the [demo](demo.md).

## Platform guides

| CI platform | Guide |
|---|---|
| GitLab CI | [platforms/gitlab.md](platforms/gitlab.md) |
| GitHub Actions | [platforms/github.md](platforms/github.md) |
| Azure DevOps | [platforms/azure-devops.md](platforms/azure-devops.md) |
| Jenkins | [platforms/jenkins.md](platforms/jenkins.md) |
| Bitbucket Pipelines | [platforms/bitbucket.md](platforms/bitbucket.md) |

## Policies and evidence

- [Scan types](scan-types.md): what each report format can prove (SAST, dependency, secrets, IaC,
  container, SBOM).
- [Scanner compatibility](compatibility.md): tested scanner versions.
- [Advanced policy](advanced-policy.md): waivers, freshness, shared targets, multi-pipeline
  releases, scanner-reported scope assurance.
- [Signed evidence (attestations)](attestations.md): Sigstore attestations bound to the pinned
  workflow, commit and run.

## Security

- [Security model](security.md): what ScanProof does and does not protect against.
- [Protected release gates](protected-release-gates.md): making ScanProof a gate that is hard to
  bypass.
- [Tested scenarios](scenarios.md): child, parallel and matrix pipelines, re-runs, faults and scale,
  with results.
- Reporting a vulnerability: [SECURITY.md](../SECURITY.md).

## Development

For contributors and maintainers. See also [CONTRIBUTING.md](../CONTRIBUTING.md).

- [Design decisions](development/design-decisions.md)
- [Production-readiness program](development/production-readiness.md)
- [Releasing](development/releasing.md)
- [Milestone records (M1–M4)](development/milestones/): historical specifications and acceptance
  criteria.
- [Live end-to-end tests](https://github.com/abdelrahman-eladwy/scanproof-e2e): the separate `scanproof-e2e` repository runs ScanProof against
  real CI platforms and scanners, and generates the fixtures in `tests/fixtures/`.
