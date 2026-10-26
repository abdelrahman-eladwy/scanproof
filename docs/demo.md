# Demo: two green pipelines, two different answers

`.github/workflows/demo.yml` runs two small release pipelines side by side in one workflow run.
Every scan job in both is **green**. ScanProof then gates each with the same kind of policy:

| Pipeline | What actually happened | Policy | ScanProof |
|---|---|---|---|
| healthy | Semgrep scanned the app; Trivy scanned the image being released (pinned digest) | [`release-ok.yaml`](../examples/demo/release-ok.yaml) | **VERIFIED**, exit 0 |
| broken | Semgrep failed on a config typo, hidden by step `continue-on-error`, and uploaded no report; Trivy scanned `alpine:3.21`, not the released image | [`release-broken.yaml`](../examples/demo/release-broken.yaml) | **BLOCKED**, exit 1 |

The workflow runs on every push to `main`. Open the latest run of **demo** in the Actions tab;
each `gate` job's summary shows the report below. The output here is from
[run 40398397491](https://github.com/abdelrahman-eladwy/scanproof/actions/runs/40398397491), copied as-is.

## Healthy pipeline: VERIFIED

```text
ScanProof 0.1.0.dev0 - verify
Policy:   demo-release-ok
Project:  abdelrahman-eladwy/scanproof
Pipeline: #40398397491  ref=fixtures/demo/run  sha=949d846e196a

[PASS] SAST  semgrep @ sast (job 121837449869)  findings=6
[PASS] CONTAINER  trivy @ container-scan (job 121837449749)  findings=2

Warnings:
  - Job 'sast-masked' succeeded, but a step failed under continue-on-error (Process completed with exit code 7).

Decision: VERIFIED  (0 failed, 0 unknown)  exit 0
Note: ScanProof verifies scan evidence, not the absence of vulnerabilities.
```

The warning is about the *broken* pipeline's job, which lives in the same workflow run. ScanProof
reports masked failures anywhere in the run, even in jobs the policy doesn't require.

## Broken pipeline: BLOCKED

```text
ScanProof 0.1.0.dev0 - verify
Policy:   demo-release-broken
Project:  abdelrahman-eladwy/scanproof
Pipeline: #40398397491  ref=fixtures/demo/run  sha=949d846e196a

[FAIL] SAST  semgrep @ sast-masked (job 121837450015)
         FAIL: FAILURE_MASKED_BY_ALLOW_FAILURE: Job 121837450015 succeeded, but a step failed under continue-on-error (Process completed with exit code 7)
         FAIL: REPORT_MISSING: semgrep.json: No artifact named 'semgrep-report-masked' in run 40398397491
[FAIL] CONTAINER  trivy @ container-scan-drift (job 121837449192)  findings=0
         FAIL: IMAGE_DIGEST_MISMATCH: Scanned alpine:3.21 (sha256:ee16d92f96db08d9d2d07da48555a27f3a69d8f0759021dbc601195ed0d2b5bd, sha256:f439434f9e6739ae2f80313f260d2084bb89feaf7220a06a5398e6b90797e2e3), expected sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

Warnings:
  - Job 'sast-masked' succeeded, but a step failed under continue-on-error (Process completed with exit code 7).

Decision: BLOCKED  (2 failed, 0 unknown)  exit 1
Note: ScanProof verifies scan evidence, not the absence of vulnerabilities.
```

Three things a green pipeline hid:

1. **Masked failure.** GitHub shows the `sast-masked` job and its step as successful. The only
   trace is the job's failure annotation (`exit code 7`), which ScanProof reads.
2. **No evidence.** The crashed scan uploaded no report, so there is nothing to bind to.
3. **Wrong artifact.** Trivy ran and passed, but on a different image. The released digest
   `sha256:d9e8…b6bc` was never scanned.

## Run it yourself

The gate step is the whole integration:

```yaml
permissions: {contents: read, actions: read, checks: read}
steps:
  - run: pip install scanproof   # until v0.1.0 is on PyPI: pip install "git+https://github.com/abdelrahman-eladwy/scanproof"
  - run: scanproof verify -P policy.yaml --pipeline "$GITHUB_RUN_ID" -p "$GITHUB_REPOSITORY"
    env:
      GITHUB_TOKEN: ${{ github.token }}
      RELEASE_IMAGE_DIGEST: sha256:...   # the digest your build pushed
```

See [usage-github.md](usage-github.md), or [usage-gitlab.md](usage-gitlab.md) for the same gate
on GitLab.
