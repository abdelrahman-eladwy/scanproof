# Signed evidence (attestations)

Without signatures, ScanProof gives *operational* assurance: anyone who can edit the pipeline can
upload a convincing fake report. With an `attestation:` block, a requirement also demands a
**Sigstore-signed in-toto attestation** that binds the report (or the image) to the CI identity
that produced it, the commit, and the run attempt where the CI provider exposes it.
An invalid signature or a report digest mismatch is rejected. These checks do not by themselves
prove that the scanner actually covered the application or that release policies are protected.

```bash
pip install "scanproof[attestations]"     # adds sigstore-python; the Docker image includes it
```

## What gets checked

For each bundle, `sigstore-python` verifies the Fulcio certificate chain, the signing time
(Rekor transparency log or an RFC 3161 timestamp), log inclusion, and the DSSE signature.
ScanProof then checks that the trust material was valid **when the bundle was signed**: every
recorded signing time must fall inside the trust root's `validFor` window of the Fulcio CA that
issued the certificate and of the transparency log, and each SCT inside its CT log's window.
sigstore-python 4.x compares those windows with the current time only, so without this a
signature made after Sigstore retired a CA or log key would verify. Only after that does
ScanProof read the claims, and then the policy is checked against them:

| Check | Fails with |
|---|---|
| Bundle verifies against a trusted Sigstore instance | `ATTESTATION_INVALID` (edited payload, swapped certificate, wrong instance...) |
| Signed while the CA, log and CT log keys were valid (trust root `validFor`) | `ATTESTATION_INVALID` ("trust material not valid at signing time") |
| Statement subject = sha256 of the report, or the image digest | `ATTESTATION_SUBJECT_MISMATCH` |
| `predicateType` is the one the policy asks for | `ATTESTATION_PREDICATE_MISMATCH` |
| Certificate issuer, source repository, Build Signer URI (regex, full match) | `ATTESTATION_SIGNER_MISMATCH` |
| `same_commit`: certificate source commit = pipeline commit | `ATTESTATION_WRONG_COMMIT` |
| `same_run`: signing run (and, on GitHub, attempt) = the verified pipeline attempt | `ATTESTATION_WRONG_RUN` |
| No bundle at all | `ATTESTATION_MISSING` |

It is UNKNOWN (exit 2), never a pass, when the bundles can't be fetched (`ATTESTATION_UNAVAILABLE`),
sigstore isn't installed or the trust root can't be loaded (`ATTESTATION_UNVERIFIABLE`), or a
claim the policy needs isn't in the certificate (`ATTESTATION_CLAIM_MISSING`, `ATTESTATION_RUN_UNKNOWN`).
For GitHub, `same_run: true` also verifies that the signed invocation URI's
`/attempts/<n>` agrees with `run_attempt` returned by the workflow run API. If either
attempt number is unavailable, the check is UNKNOWN (`ATTESTATION_RUN_UNKNOWN`), not a
success. A mismatch is a definite failure. GitLab's `same_run` still binds the
certificate's job ID to a job in the inspected pipeline.

If several bundles exist for one subject (re-runs, other workflows), one acceptable bundle is
enough, and the report lists why each of the others was rejected.

## Policy

```yaml
requirements:
  - id: SAST
    tool: semgrep
    job_name: sast
    artifact_name: semgrep-report
    report_path: semgrep.json
    attestation:
      source: platform              # GitHub attestations API; or: artifact (+ bundle_path)
      subject: report               # sha256 of semgrep.json; or: image (uses image_digest_must_match)
      predicate_type: https://slsa.dev/provenance/v1   # the default
      signer:
        issuer: https://token.actions.githubusercontent.com
        repository: https://github.com/my-org/my-app
        workflow: 'https://github\.com/my-org/my-app/\.github/workflows/ci\.yml@refs/heads/main'
      same_commit: true             # the default
      same_run: true                # the default
```

- `signer` must pin `repository` and/or `workflow`. An issuer alone would accept a signature from
  any repository on GitHub, so ScanProof refuses to load such a policy.
- `workflow` is a regular expression matched against the **whole** Build Signer URI. Escape dots.
- **Reusable workflows:** the Build Signer URI is the *reusable* workflow file (the one that ran
  the signing step), not the caller. Pin the reusable workflow, ideally at a tag or commit.
- `source: artifact` reads `bundle_path` from the job's artifacts (GitLab) or from the run
  artifact `attestation.artifact_name` (default: the requirement's `artifact_name`).
- `predicate_type: https://scanproof.dev/sigstore/message-signature` accepts a plain signature
  over the report bytes (`sigstore sign`, `cosign sign-blob --bundle`), which has no statement.

## Producing attestations

**GitHub Actions** (what the [`attestation-contract` workflow](https://github.com/abdelrahman-eladwy/scanproof-e2e/blob/main/.github/workflows/attestation-contract.yml) runs live):

```yaml
permissions: {contents: read, id-token: write, attestations: write}
steps:
  - run: semgrep scan --json --output semgrep.json .
  - uses: actions/attest-build-provenance@<sha>   # SLSA provenance for the report
    with: {subject-path: semgrep.json}
  - uses: actions/upload-artifact@<sha>
    with: {name: semgrep-report, path: semgrep.json}
```

For an image scan, `actions/attest` with `subject-digest: sha256:...` and
`predicate-type: https://cosign.sigstore.dev/attestation/vuln/v1` signs "Trivy scanned exactly this
digest". The gate job needs `attestations: read` (plus `actions: read`, `checks: read`).

**GitLab CI** (gitlab.com; keyless signing needs an ID token with audience `sigstore`):

```yaml
semgrep:
  id_tokens:
    SIGSTORE_ID_TOKEN: {aud: sigstore}
  script:
    - semgrep scan --json --output semgrep.json .
    - cosign sign-blob semgrep.json --bundle semgrep.json.sigstore.json --yes
  artifacts:
    paths: [semgrep.json, semgrep.json.sigstore.json]
```

with `source: artifact`, `bundle_path: semgrep.json.sigstore.json`, the message-signature
predicate type, and `issuer: https://gitlab.com`. On GitLab the Build Signer URI is
`https://gitlab.com/<project>//<ci config path>@<ref>` (note the double slash), and `same_run`
matches when the certificate's job (`/-/jobs/<id>`) belongs to the verified pipeline. GitLab has
no attestation store, so `source: platform` is GitHub-only. *The GitLab path is unit-tested
against Fulcio's documented claim format; there is no live GitLab-signed fixture yet.*

## Trust roots

By default ScanProof trusts **Sigstore public-good**, refreshed over TUF (network access to
`tuf-repo-cdn.sigstore.dev`). Options:

- `--sigstore-offline`: use the trust root shipped with sigstore-python (no network; may go stale
  when Sigstore rotates keys).
- `--sigstore-trusted-root FILE` (repeatable): trusted_root.json, or JSON lines of them. **Private
  GitHub repositories** sign with GitHub's own Sigstore instance; get its root with
  `gh attestation trusted-root > roots.jsonl`. A bundle is valid if it verifies against any root.

A replay from **another project** (its genuine report and bundle copied into this run, even a
fork at the same commit) fails the repository pin (`ATTESTATION_SIGNER_MISMATCH`) and the run
check (`ATTESTATION_WRONG_RUN`). Only a signer without `repository` plus `same_run: false` would
accept it, and `assurance.profile: production` rejects both. Timestamp authorities' own `validFor`
windows are not checked against the signing time.

`scanproof attestation -b bundle.json [-f report.json]` verifies bundles and prints the claims
ScanProof would judge, which helps when writing the `signer` block.

## What this does and does not prove

It proves the report (or image scan) was signed by the named workflow file, at the named commit,
in the verified run, through an OIDC identity the CI platform issued. It does **not** stop someone
who can push to the ref the workflow runs from: they can change the workflow and sign whatever
they like. Pin `workflow` to a protected ref (or a tag), protect that branch and the workflow file
with CODEOWNERS, and keep the gate where the application team can't edit it
(see [security.md](security.md)).
