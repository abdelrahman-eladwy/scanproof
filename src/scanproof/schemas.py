"""Published, versioned JSON Schemas for ScanProof inputs and outputs (Phase 4, #47).

`documents()` is the single source; `scripts/export_schemas.py` writes it to `schemas/`
and CI fails if the committed files drift. Schemas describe the format, not a verdict:
a document that validates can still be BLOCKED or INDETERMINATE.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from scanproof.contracts import (
    EVIDENCE_SCHEMA,
    INSPECTION_SCHEMA,
    POLICY_API_VERSION,
    RELEASE_SCHEMA,
    SCHEMA_URL_BASE,
    VERIFICATION_SCHEMA,
)
from scanproof.evidence.models import ScanEvidence
from scanproof.models import InspectionReport
from scanproof.policy.models import Policy
from scanproof.release import Release, ReleaseReport
from scanproof.verification import VerificationErrorReport, VerificationReport

DRAFT = "https://json-schema.org/draft/2020-12/schema"


def _tag(identifier: str) -> str:
    """'scanproof.dev/verification/v1alpha1' -> 'v1alpha1'."""
    return identifier.rsplit("/", 1)[-1]


# filename -> (model, contract identifier, mode, title)
_CATALOG: dict[str, tuple[type[BaseModel], str, str, str]] = {
    f"policy.{_tag(POLICY_API_VERSION)}.schema.json": (
        Policy,
        POLICY_API_VERSION,
        "validation",
        "ScanProof PipelineAssurancePolicy (input)",
    ),
    f"release.{_tag(POLICY_API_VERSION)}.schema.json": (
        Release,
        POLICY_API_VERSION,
        "validation",
        "ScanProof ReleaseAssurance (input)",
    ),
    f"inspection-report.{_tag(INSPECTION_SCHEMA)}.schema.json": (
        InspectionReport,
        INSPECTION_SCHEMA,
        "serialization",
        "scanproof inspect output",
    ),
    f"evidence.{_tag(EVIDENCE_SCHEMA)}.schema.json": (
        ScanEvidence,
        EVIDENCE_SCHEMA,
        "serialization",
        "scanproof evidence output",
    ),
    f"verification-report.{_tag(VERIFICATION_SCHEMA)}.schema.json": (
        VerificationReport,
        VERIFICATION_SCHEMA,
        "serialization",
        "scanproof verify output",
    ),
    f"verification-error.{_tag(VERIFICATION_SCHEMA)}.schema.json": (
        VerificationErrorReport,
        VERIFICATION_SCHEMA,
        "serialization",
        "scanproof verify -o output when the pipeline could not be read (exit 2)",
    ),
    f"release-report.{_tag(RELEASE_SCHEMA)}.schema.json": (
        ReleaseReport,
        RELEASE_SCHEMA,
        "serialization",
        "scanproof verify-release output",
    ),
}


def documents() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for filename, (model, contract, mode, title) in _CATALOG.items():
        body = model.model_json_schema(mode=mode)  # type: ignore[arg-type]
        out[filename] = {
            "$schema": DRAFT,
            "$id": SCHEMA_URL_BASE + filename,
            "title": title,
            "x-scanproof-contract": contract,
            **{k: v for k, v in body.items() if k != "title"},
        }
    return out
