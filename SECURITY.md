# Security policy

ScanProof is a security tool, so a bug that makes it report VERIFIED when evidence is missing,
invalid or for the wrong artifact is a **security vulnerability**, not just a bug.

## Reporting a vulnerability

Please report privately through GitHub:
**[Report a vulnerability](https://github.com/abdelrahman-eladwy/scanproof/security/advisories/new)**
(Security tab > Advisories > Report a vulnerability).

Do not open a public issue for:
- false VERIFIED results (a missing, failed, masked, stale or foreign scan accepted as valid),
- credential exposure (token in logs, output, errors, or sent to another host),
- TLS, redirect or download-limit bypasses.

Include the ScanProof version, the policy (redacted), and the inspection/verification JSON if possible.

## What to expect

This is a volunteer project. Expect an acknowledgement within 7 days and a fix or mitigation plan
within 30 days for confirmed issues. You will be credited in the advisory unless you prefer not to be.

## Supported versions

Only the latest release receives fixes while the project is pre-1.0.

## Scope and limits

ScanProof v0.x provides *operational* assurance, not tamper-proof evidence; see
[docs/security.md](docs/security.md). "Someone with write access to the pipeline can forge a
report" is a known, documented limitation, not a vulnerability.
