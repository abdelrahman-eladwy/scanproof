"""Policy file format: scanproof.dev/v1alpha1 PipelineAssurancePolicy.

Every model forbids unknown keys, so a typo such as `job_sucess: true` is a load
error instead of a silently disabled control.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

_ENV_REF = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


class PolicyError(Exception):
    """The policy file is missing, malformed or invalid. Maps to exit code 3."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Checks(_Strict):
    # job
    job_success: bool = Field(True, description="Latest attempt must have status success")
    same_commit: bool = Field(True, description="Job commit SHA must equal the pipeline SHA")
    # report
    report_required: bool = Field(True, description="A parseable report must be present")
    scanner_errors_allowed: int | None = Field(
        None, ge=0, description="Max scanner errors; unset = not checked"
    )
    ignore_scanner_warnings: bool = Field(
        False, description="Do not count errors with level warn/warning/info"
    )
    minimum_scanned_files: int | None = Field(None, ge=0)
    required_paths: list[str] | None = Field(
        None, description="Each prefix must match at least one scanned path"
    )
    image_digest_must_match: str | None = Field(
        None, description="sha256:... digest (or ${ENV_VAR}) the scanned image must have"
    )
    expected_scanner: str | None = Field(
        None,
        description="Engine that must have produced the report (e.g. CodeQL inside SARIF); "
        "case-insensitive",
    )
    minimum_components: int | None = Field(None, ge=0, description="SBOM: minimum components")
    minimum_resources: int | None = Field(
        None, ge=0, description="IaC: minimum resources the scanner evaluated"
    )

    @field_validator("image_digest_must_match")
    @classmethod
    def _expand_digest(cls, value: str | None) -> str | None:
        if value is None:
            return None
        match = _ENV_REF.match(value.strip())
        if match:
            var = match.group(1)
            resolved = os.environ.get(var, "").strip()
            if not resolved:
                raise ValueError(f"environment variable {var} is not set")
            value = resolved
        _, _, digest = value.strip().rpartition("@")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError(f"expected a sha256:<64 hex> digest, got {value!r}")
        return digest


SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"


class SignerPolicy(_Strict):
    """Who must have signed the attestation, matched against the Fulcio certificate claims."""

    issuer: str = Field(description="OIDC issuer, e.g. https://token.actions.githubusercontent.com")
    repository: str | None = Field(
        None, description="Source repository URI, exact (e.g. https://github.com/org/app)"
    )
    workflow: str | None = Field(
        None,
        description="Regex that must fully match the Build Signer URI, e.g. "
        r"'https://github\.com/org/app/\.github/workflows/ci\.yml@refs/heads/main'",
    )

    @model_validator(mode="after")
    def _pinned(self) -> SignerPolicy:
        # An issuer alone accepts anyone with a GitHub (or GitLab) account.
        if not self.repository and not self.workflow:
            raise ValueError("signer must pin repository and/or workflow, not only the issuer")
        if self.workflow:
            try:
                re.compile(self.workflow)
            except re.error as exc:
                raise ValueError(f"workflow is not a valid regex: {exc}") from None
        return self


class AttestationRequirement(_Strict):
    """A signed in-toto attestation (Sigstore bundle) must exist for the report or the image."""

    source: Literal["artifact", "platform"] = Field(
        description="artifact: a bundle file next to the report; platform: the CI platform's "
        "attestation store (GitHub attestations API)"
    )
    bundle_path: str | None = Field(None, description="artifact: path of the bundle file")
    artifact_name: str | None = Field(
        None, description="GitHub: run artifact holding bundle_path (default: the report's)"
    )
    subject: Literal["report", "image"] = Field(
        "report", description="report: sha256 of the report file; image: image_digest_must_match"
    )
    predicate_type: str = SLSA_PROVENANCE_V1
    signer: SignerPolicy
    same_commit: bool = Field(True, description="Certificate source digest = pipeline commit")
    same_run: bool = Field(True, description="Certificate run = the verified pipeline / run")

    @model_validator(mode="after")
    def _bundle_path(self) -> AttestationRequirement:
        if self.source == "artifact" and not self.bundle_path:
            raise ValueError("source: artifact needs bundle_path")
        if self.source == "platform" and (self.bundle_path or self.artifact_name):
            raise ValueError("bundle_path / artifact_name are only used with source: artifact")
        return self


class AppliesTo(_Strict):
    refs: list[str] = Field(description="Glob patterns for pipeline refs, e.g. main, release/*")


class Requirement(_Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    description: str | None = None
    tool: str
    job_name: str
    report_path: str
    artifact_name: str | None = Field(
        None, description="GitHub: name of the run artifact (zip) that contains report_path"
    )
    applies_to: AppliesTo | None = None
    checks: Checks = Field(default_factory=Checks)
    attestation: AttestationRequirement | None = None

    @model_validator(mode="after")
    def _attestation_subject(self) -> Requirement:
        if (
            self.attestation
            and self.attestation.subject == "image"
            and not self.checks.image_digest_must_match
        ):
            raise ValueError("attestation subject: image needs checks.image_digest_must_match")
        return self


class ProjectRef(_Strict):
    provider: Literal["gitlab", "github"]
    id: str

    @field_validator("id", mode="before")
    @classmethod
    def _coerce_id(cls, value: object) -> object:
        return str(value) if isinstance(value, int) else value


class Enforcement(_Strict):
    on_failure: Literal["block"] = "block"
    on_unknown: Literal["block", "warn"] = "block"
    # When applies_to excludes every requirement nothing was verified. A release gate must not
    # read that as VERIFIED unless the policy says so explicitly.
    on_nothing_applicable: Literal["block", "allow"] = "block"


class Metadata(_Strict):
    name: str


class Policy(_Strict):
    apiVersion: Literal["scanproof.dev/v1alpha1"]
    kind: Literal["PipelineAssurancePolicy"]
    metadata: Metadata | None = None
    project: ProjectRef
    requirements: list[Requirement] = Field(min_length=1)
    enforcement: Enforcement = Field(default_factory=Enforcement)

    @model_validator(mode="after")
    def _unique_ids_and_known_tools(self) -> Policy:
        from scanproof.scanners import ADAPTERS

        seen: set[str] = set()
        for req in self.requirements:
            if req.id in seen:
                raise ValueError(f"duplicate requirement id {req.id!r}")
            seen.add(req.id)
            if self.project.provider == "github" and not req.artifact_name:
                raise ValueError(
                    f"requirement {req.id}: GitHub artifacts belong to the run, not a job; "
                    "set artifact_name"
                )
            if (
                req.attestation
                and req.attestation.source == "platform"
                and self.project.provider != "github"
            ):
                raise ValueError(
                    f"requirement {req.id}: {self.project.provider} has no attestation store; "
                    "use attestation.source: artifact"
                )
            if req.tool.lower() not in ADAPTERS:
                raise ValueError(
                    f"requirement {req.id}: unsupported tool {req.tool!r} "
                    f"(supported: {', '.join(sorted(ADAPTERS))})"
                )
        return self

    @property
    def name(self) -> str:
        return self.metadata.name if self.metadata else "unnamed-policy"


def load_policy(path: Path) -> Policy:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc.strerror}") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy {path} is not valid YAML: {exc}") from None
    if not isinstance(data, dict):
        raise PolicyError(f"policy {path} must be a YAML mapping")
    try:
        return Policy.model_validate(data)
    except ValidationError as exc:
        lines = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"]) or "(root)"
            msg = "unknown field" if err["type"] == "extra_forbidden" else err["msg"]
            lines.append(f"  - {loc}: {msg}")
        raise PolicyError(f"policy {path} is invalid:\n" + "\n".join(lines)) from None
