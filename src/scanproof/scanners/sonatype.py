"""Sonatype IQ / Lifecycle application report adapter (EXPERIMENTAL).

Format: the IQ Server raw application report (`components[]` + `matchSummary`), as returned by
`GET /api/v2/applications/{publicId}/reports/{scanId}/raw`. This is NOT the policy-result file
written by `nexus-iq-cli -r`. Tested against real report samples from DefectDojo's test suite
(BSD-3-Clause, see tests/fixtures/LICENSE-DefectDojo.md), not against a live IQ Server.

Mapping:
  matchSummary.totalComponentCount     scope.components (falls back to len(components))
  components[].securityData.securityIssues[]
                                       findings by threatCategory (critical/severe/moderate/low);
                                       issues with status "Waived" are counted as suppressed
The format has no section for scan errors, so scanner errors are unknown.
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScanScope, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by


class SonatypeIqAdapter(ScannerAdapter):
    tool = "sonatype-iq"
    scan_type = ScanType.DEPENDENCY

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict):
            return "Sonatype report must be a JSON object"
        if not isinstance(data.get("components"), list):
            return "Not a Sonatype IQ raw report: missing components list"
        if "matchSummary" in data and not isinstance(data["matchSummary"], dict):
            return "Sonatype 'matchSummary' must be an object"
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        components = data["components"]
        summary = data.get("matchSummary") or {}
        total = summary.get("totalComponentCount")
        severities: list[str] = []
        waived = 0
        for comp in components:
            issues = ((comp or {}).get("securityData") or {}).get("securityIssues") or []
            for issue in issues:
                if str(issue.get("status", "")).lower() == "waived":
                    waived += 1
                    continue
                severities.append(str(issue.get("threatCategory") or "UNKNOWN").upper())
        return {
            "tool_version": None,
            "scanner_name": "sonatype-iq",
            "scanner_errors": None,
            "scope": ScanScope(
                components=int(total) if isinstance(total, int) else len(components)
            ),
            "results_reported": True,
            "findings": FindingsSummary(
                total=len(severities), by_severity=count_by(severities), suppressed=waived
            ),
        }
