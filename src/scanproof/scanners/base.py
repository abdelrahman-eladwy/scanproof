"""Scanner adapter contract.

An adapter converts raw report bytes into `ScanEvidence`. Adapters must never raise on
bad input: a missing, empty, truncated or foreign report is itself evidence, and is
returned as `present=False` or `parseable=False` with a reason.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from scanproof.evidence.models import ScanEvidence, ScanType

INVALID_JSON = "Report is not valid JSON"


class ReportLoadError(Exception):
    """The report bytes could not be decoded; becomes parseable=False with this message."""


class ScannerAdapter(ABC):
    tool: ClassVar[str]
    scan_type: ClassVar[ScanType]

    def parse(self, raw: bytes | None) -> ScanEvidence:
        if raw is None:
            return self._evidence(present=False, parseable=False, parse_error="No report obtained")

        digest = hashlib.sha256(raw).hexdigest()
        base: dict[str, Any] = {"report_sha256": digest, "report_bytes": len(raw)}

        if not raw.strip():
            return self._evidence(
                present=True, parseable=False, parse_error="Report is empty", **base
            )
        try:
            data = self.load(raw)
        except ReportLoadError as exc:
            return self._evidence(present=True, parseable=False, parse_error=str(exc), **base)

        problem = self.shape_problem(data)
        if problem:
            return self._evidence(present=True, parseable=False, parse_error=problem, **base)

        try:
            fields = self.extract(data)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            return self._evidence(
                present=True,
                parseable=False,
                parse_error=f"Unexpected {self.tool} report structure: {type(exc).__name__}: {exc}",
                **base,
            )
        return self._evidence(present=True, parseable=True, **base, **fields)

    def load(self, raw: bytes) -> Any:
        """Decode report bytes. JSON by default; non-JSON formats (e.g. Fortify FPR) override."""
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ReportLoadError(f"{INVALID_JSON}: {exc}") from None

    @abstractmethod
    def shape_problem(self, data: Any) -> str | None:
        """Return a reason if `data` is not this tool's report format, else None."""

    @abstractmethod
    def extract(self, data: Any) -> dict[str, Any]:
        """Map a well-shaped report onto ScanEvidence fields."""

    def _evidence(self, **fields: Any) -> ScanEvidence:
        # An adapter may refine the scan type from report content (e.g. Trivy fs vs image).
        scan_type = fields.pop("scan_type", None) or self.scan_type
        return ScanEvidence(tool=self.tool, scan_type=scan_type, **fields)


def count_by(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return dict(sorted(counts.items()))
