# Live contract tests

Unit tests run offline against recorded fixtures. These files support the **live** contract
workflows in `.github/workflows/`, which run ScanProof against real CI platforms to prove the
fixtures still match reality. They are test inputs, not examples to copy: for those, see
[`examples/`](../../examples/).

| Path | Used by | What it checks |
|---|---|---|
| `policies/github-self-*.yaml` | `github-contract.yml`, `tests/unit/test_github_connector.py` | Masked steps and jobs, skipped jobs, matrices, reusable workflows on this repo's own runs |
| `policies/attest-self-*.yaml` | `attestation-contract.yml` | Sigstore attestations: correct signer, wrong signer, reusable-workflow pinning |
| `policies/github-release-contract-*.yaml` | `release-gate-contract.yml` | A failed ScanProof gate blocks the downstream deployment |
| `policies/jenkins/*.yaml` | `platforms-contract.yml`, `tests/unit/test_jenkins.py` | One policy per Jenkins masking pattern (failed, masked, skipped, retry, try/catch, unstable, parallel, matrix) |
| `jenkins/` | `platforms-contract.yml` | Throwaway Jenkins (configuration as code) running one pipeline per masking pattern |

The Jenkins policy names match the job names in `jenkins/jobs.groovy` and the recorded
`tests/fixtures/jenkins-real/` directories, so rename them only together.

## Running

Each workflow can be started manually (**Actions > workflow > Run workflow**). To also have it
commit the collected responses back for review, push to a disposable branch matching its trigger
(`fixtures/github/<name>`, `fixtures/attest/<name>`, `fixtures/gate/<name>`,
`fixtures/platforms/<name>`, `fixtures/gitlab/<name>`), copy the reviewed files into
`tests/fixtures/`, then **delete the branch**. See [`tests/fixtures/README.md`](../fixtures/README.md).
