"""Bitbucket Code Insights report, as assembled by the Bitbucket connector:
{"format": "scanproof.dev/bitbucket-code-insights/v1", "report": {...}, "annotations": [...],
 "annotations_complete": bool}.

Code Insights is a summary format: it has no scan scope and no scanner errors (both unknown).
Findings are the report's annotations, counted only when every page was read.
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by

FORMAT = "scanproof.dev/bitbucket-code-insights/v1"
_TYPES = {"SECURITY": ScanType.OTHER, "BUG": ScanType.SAST, "COVERAGE": ScanType.OTHER}


class BitbucketCodeInsightsAdapter(ScannerAdapter):
    tool = "bitbucket-code-insights"
    scan_type = ScanType.OTHER

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict) or data.get("format") != FORMAT:
            return "Not a Bitbucket Code Insights report fetched by ScanProof"
        if not isinstance(data.get("report"), dict) or not isinstance(
            data.get("annotations"), list
        ):
            return "Code Insights document is missing report or annotations"
        if str(data["report"].get("result") or "").upper() == "PENDING":
            return "Code Insights report is still PENDING (the scan has not finished)"
        return None

    def extract(self, data: Any) -> dict[str, Any]:
        report = data["report"]
        notes = [a for a in data["annotations"] if isinstance(a, dict)]
        findings = None
        if data.get("annotations_complete") is True:
            severities = [str(a.get("severity") or "UNKNOWN").upper() for a in notes]
            findings = FindingsSummary(total=len(notes), by_severity=count_by(severities))
        reporter = report.get("reporter")
        return {
            "scan_type": _TYPES.get(str(report.get("report_type")), ScanType.OTHER),
            "scanner_name": str(reporter or report.get("title") or "")[:200] or None,
            "results_reported": True,
            "findings": findings,
        }
