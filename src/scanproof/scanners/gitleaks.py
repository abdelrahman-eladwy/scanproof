"""Gitleaks native JSON report (`gitleaks dir|git --report-format json`), tested with v8.30.

The report is a JSON array of findings; `[]` means no secrets were found. Gitleaks does not
report which files it read, nor its own errors, so scope and scanner errors are unknown.
Secret values are never read (run gitleaks with --redact); author / email fields are ignored.
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScanType
from scanproof.scanners.base import ScannerAdapter

_KEYS = {"RuleID", "File"}


class GitleaksAdapter(ScannerAdapter):
    tool = "gitleaks"
    scan_type = ScanType.SECRETS

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, list):
            return "Gitleaks JSON report must be a list of findings"
        if any(not isinstance(f, dict) or not set(f) >= _KEYS for f in data):
            return "Not a Gitleaks report: findings need RuleID and File"
        return None

    def extract(self, data: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "scanner_name": "gitleaks",
            "results_reported": True,
            "findings": FindingsSummary(total=len(data), by_severity={}),
            "scanner_errors": None,
        }
