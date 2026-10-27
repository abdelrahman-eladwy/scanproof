"""`scanproof verify-release`: one release made of several pipelines, possibly on different
platforms (backend on GitLab, frontend on GitHub, chart on Jenkins...).

A release file lists components; each is verified with its own policy against its own pipeline.
The release is VERIFIED only if every component is; one BLOCKED component blocks it; otherwise
any component that could not be verified makes it INDETERMINATE.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from scanproof import __version__
from scanproof.connectors.base import CIConnector, ConnectorError
from scanproof.policy.engine import Decision
from scanproof.policy.models import PolicyError, load_policy
from scanproof.verification import VerificationReport, verify_pipeline

_ENV_REF = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
MAX_COMPONENTS = 50


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Component(_Strict):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    policy: str = Field(description="Policy file, relative to the release file")
    pipeline: int = Field(description="Pipeline / run / build id, or ${ENV_VAR}")
    project: str | None = Field(None, description="Override the policy's project")
    url: str | None = Field(None, description="Platform URL for this component")

    @field_validator("pipeline", mode="before")
    @classmethod
    def _env(cls, value: object) -> object:
        if isinstance(value, str):
            match = _ENV_REF.match(value.strip())
            if match:
                resolved = os.environ.get(match.group(1), "").strip()
                if not resolved:
                    raise ValueError(f"environment variable {match.group(1)} is not set")
                return resolved
        return value


class Metadata(_Strict):
    name: str


class Release(_Strict):
    apiVersion: Literal["scanproof.dev/v1alpha1"]
    kind: Literal["ReleaseAssurance"]
    metadata: Metadata
    components: list[Component] = Field(min_length=1, max_length=MAX_COMPONENTS)

    @model_validator(mode="after")
    def _unique(self) -> Release:
        names = [c.name for c in self.components]
        if len(names) != len(set(names)):
            raise ValueError("component names must be unique")
        return self


class ComponentResult(BaseModel):
    name: str
    policy: str
    provider: str | None = None
    project: str | None = None
    pipeline: int
    decision: Decision
    exit_code: int
    report: VerificationReport | None = None
    error: str | None = Field(None, description="Why the component could not be verified")


class ReleaseReport(BaseModel):
    schema_version: str = "scanproof.dev/release/v1alpha1"
    scanproof_version: str = __version__
    generated_at: datetime
    release: str
    decision: Decision
    exit_code: int
    components: list[ComponentResult]


def load_release(path: Path) -> Release:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"cannot read release file {path}: {exc.strerror}") from None
    except yaml.YAMLError as exc:
        raise PolicyError(f"release file {path} is not valid YAML: {exc}") from None
    try:
        return Release.model_validate(data)
    except ValidationError as exc:
        lines = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"]) or "(root)"
            msg = "unknown field" if err["type"] == "extra_forbidden" else err["msg"]
            lines.append(f"  - {loc}: {msg}")
        raise PolicyError(f"release file {path} is invalid:\n" + "\n".join(lines)) from None


def combine_decisions(decisions: list[Decision]) -> Decision:
    if Decision.BLOCKED in decisions:
        return Decision.BLOCKED
    if Decision.INDETERMINATE in decisions:
        return Decision.INDETERMINATE
    return Decision.VERIFIED


def verify_release(
    release: Release,
    base_dir: Path,
    connect: Callable[[str, str | None], CIConnector],
    **verify_kwargs: object,
) -> ReleaseReport:
    """`connect(provider, url)` builds a connector; it may raise ConnectorError or SystemExit
    (usage errors such as a missing token). Policies are loaded up front so a typo in any of
    them is a usage error before anything is fetched."""
    policies = {}
    for c in release.components:
        policy_path = (base_dir / c.policy).resolve()
        policies[c.name] = (policy_path, load_policy(policy_path))

    results = []
    for c in release.components:
        policy_path, policy = policies[c.name]
        project = c.project or policy.project.id
        common = {"name": c.name, "policy": str(c.policy), "pipeline": c.pipeline}
        try:
            with connect(policy.project.provider, c.url) as conn:
                report = verify_pipeline(
                    conn,
                    policy,
                    instance_url=conn.base_url,
                    project=project,
                    pipeline_id=c.pipeline,
                    **verify_kwargs,
                )
            results.append(
                ComponentResult(
                    **common,
                    provider=policy.project.provider,
                    project=project,
                    decision=report.decision,
                    exit_code=report.exit_code,
                    report=report,
                )
            )
        except ConnectorError as exc:
            results.append(
                ComponentResult(
                    **common,
                    provider=policy.project.provider,
                    project=project,
                    decision=Decision.INDETERMINATE,
                    exit_code=Decision.INDETERMINATE.exit_code,
                    error=f"{exc.kind.value}: {exc.message}",
                )
            )
    decision = combine_decisions([r.decision for r in results])
    return ReleaseReport(
        generated_at=datetime.now(UTC),
        release=release.metadata.name,
        decision=decision,
        exit_code=decision.exit_code,
        components=results,
    )
