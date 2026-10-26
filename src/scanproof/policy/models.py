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


class AppliesTo(_Strict):
    refs: list[str] = Field(description="Glob patterns for pipeline refs, e.g. main, release/*")


class Requirement(_Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    description: str | None = None
    tool: str
    job_name: str
    report_path: str
    applies_to: AppliesTo | None = None
    checks: Checks = Field(default_factory=Checks)


class ProjectRef(_Strict):
    provider: Literal["gitlab"]
    id: str

    @field_validator("id", mode="before")
    @classmethod
    def _coerce_id(cls, value: object) -> object:
        return str(value) if isinstance(value, int) else value


class Enforcement(_Strict):
    on_failure: Literal["block"] = "block"
    on_unknown: Literal["block", "warn"] = "block"


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
