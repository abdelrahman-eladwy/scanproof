# ScanProof: design decisions

*Draft write-up of the choices behind v0.1, for a blog or LinkedIn post.*

## The problem

Most pipelines treat "the security job is green" as "the security scan happened". Those are
different claims. A scan job can be green while:

- it was removed from the pipeline by a `rules:` change and nobody noticed,
- it failed, but `allow_failure: true` let the pipeline carry on,
- it succeeded and uploaded no report, or an empty, truncated or wrong-tool report,
- Semgrep hit syntax errors and silently skipped the files that mattered,
- Trivy scanned `myapp:latest`, which is not the image being deployed.

ScanProof checks the *evidence* a scan left behind and answers one question: did the scans this
release depends on really run, completely, against what we are about to ship?

## 1. Unknown is never pass

Every check returns PASS, FAIL, UNKNOWN or NOT_APPLICABLE. If ScanProof cannot see something
(token lacks access, job still running, report doesn't state its scope) the answer is UNKNOWN,
and by default UNKNOWN blocks. The data model enforces this: a field a report doesn't provide is
`None`, never `0`. "Zero findings" and "we don't know" are different facts, and conflating them
is how security gates produce false confidence.

Example: Trivy's JSON has no section for the scanner's own errors, so ScanProof reports Trivy
scanner errors as *unknown*, not as an empty list a policy could count as zero.

## 2. Check the scan, not the code

A scan can run perfectly and find critical vulnerabilities; that is a successful scan. ScanProof
reports findings for context but never judges them. Vulnerability triage belongs to the tools
built for it. Keeping that line sharp keeps the product honest and small.

## 3. Bind evidence to the artifact

"Trivy succeeded" is weak. "Trivy scanned `sha256:a0f5…`, and that is the digest we're
deploying" is strong. ScanProof reads the image digest out of the Trivy report and compares it
with the digest the build pushed.

## 4. Be explicit about the trust boundary

v0.1 gives *operational* assurance: it catches mistakes, drift and silent failures. It does not
stop someone who can edit the pipeline from forging a report. The docs say this plainly and show
where to run the gate so it is harder to bypass. Cryptographic evidence (attestations, SLSA
provenance) is the next step, and ScanProof's own releases already ship with signed provenance.

## 5. Strict by default, impossible to weaken by typo

Policies are YAML with unknown keys rejected. `job_sucess: true` is a load error, not a silently
disabled control. Defaults are strict: the job must succeed, run on the pipeline commit, and
upload a parseable report.

## 6. Small, boring architecture

A modular monolith CLI: connector (GitLab) → scanner adapters → unified evidence → pure policy
engine → report. No server, no database. Adding Fortify or GitHub Actions means one adapter or
connector; the policy engine doesn't change. Exit codes are a contract: 0 verified, 1 blocked,
2 indeterminate, 3 usage error, with usage errors deliberately kept off code 2 so a typo is never
read as "couldn't verify".

## 7. Tested against reality

Parser tests use real Semgrep and Trivy output generated in CI, not hand-written JSON. Every
scenario from the design table (absent job, masked failure, missing report, 403, wrong commit,
wrong image, retried job) is an end-to-end test, and the security-critical checks were mutation
tested: disabling any of them makes a test fail.
