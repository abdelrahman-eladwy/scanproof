"""What a verified attestation says. Pure data, importable without the sigstore extra."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class AttestationStatus(StrEnum):
    VERIFIED = "verified"  # certificate chain, transparency log / timestamp, DSSE signature: all OK
    INVALID = "invalid"  # cryptographic verification failed, or not an in-toto statement
    UNVERIFIABLE = "unverifiable"  # could not check (sigstore not installed, no trust root)


class SignerClaims(BaseModel):
    """Identity claims from the Fulcio certificate's OIDC extensions (OID 1.3.6.1.4.1.57264.1.*).

    On GitHub Actions: `build_signer_uri` is the workflow file that ran the signing job (for a
    reusable workflow, the reusable file), `build_config_uri` is the top-level workflow.
    """

    issuer: str | None = None
    build_signer_uri: str | None = None
    build_signer_digest: str | None = None
    build_config_uri: str | None = None
    runner_environment: str | None = None
    source_repository_uri: str | None = None
    source_repository_digest: str | None = None
    source_repository_ref: str | None = None
    run_invocation_uri: str | None = None
    san: list[str] = Field(default_factory=list, description="Certificate SANs")


class Subject(BaseModel):
    name: str | None = None
    digest: dict[str, str] = Field(default_factory=dict)


class AttestationEvidence(BaseModel):
    status: AttestationStatus
    reason: str | None = Field(default=None, description="Why it is invalid / unverifiable")
    origin: str | None = Field(default=None, description="Where the bundle came from")
    bundle_sha256: str | None = None
    statement_type: str | None = None
    predicate_type: str | None = None
    subjects: list[Subject] = Field(default_factory=list)
    signer: SignerClaims | None = None
    predicate_summary: dict[str, str] = Field(
        default_factory=dict, description="A few predicate fields for the report (builder id...)"
    )
    run_matches: bool | None = Field(
        default=None,
        description="Set by the orchestrator: the certificate's run is the verified pipeline "
        "(None = could not tell)",
    )

    @model_validator(mode="after")
    def _claims_only_when_verified(self) -> AttestationEvidence:
        # The engine trusts these fields. They must never come from an unverified bundle.
        if self.status is not AttestationStatus.VERIFIED and (
            self.signer is not None or self.subjects or self.predicate_type
        ):
            raise ValueError("claims are only allowed on a verified attestation")
        return self

    def subject_digests(self, algorithm: str = "sha256") -> set[str]:
        return {s.digest[algorithm].lower() for s in self.subjects if algorithm in s.digest}
