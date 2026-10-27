"""Signed evidence: Sigstore bundles carrying in-toto statements (SLSA provenance, scan results).

`verify.py` does the cryptography through the `sigstore` library (optional extra
`scanproof[attestations]`) and returns `AttestationEvidence`. Claims (subjects, predicate, signer
identity) are only ever filled in after the bundle verified, so the policy engine can compare them
without doing any I/O or cryptography itself.
"""

from scanproof.attestation.models import AttestationEvidence, AttestationStatus, SignerClaims

__all__ = ["AttestationEvidence", "AttestationStatus", "SignerClaims"]
