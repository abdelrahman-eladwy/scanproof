"""Versioned public contract identifiers (Phase 4, #47).

Leaf module: no imports from scanproof, so every model can use these without cycles.
Changing a value here is a breaking change to a published format; see docs/compatibility.md.
"""

from __future__ import annotations

from typing import Final

POLICY_API_VERSION: Final = "scanproof.dev/v1alpha1"
INSPECTION_SCHEMA: Final = "scanproof.dev/inspection/v1alpha1"
EVIDENCE_SCHEMA: Final = "scanproof.dev/evidence/v1alpha1"
VERIFICATION_SCHEMA: Final = "scanproof.dev/verification/v1alpha1"
RELEASE_SCHEMA: Final = "scanproof.dev/release/v1alpha1"

SCHEMA_URL_BASE: Final = (
    "https://raw.githubusercontent.com/abdelrahman-eladwy/scanproof/main/schemas/"
)
