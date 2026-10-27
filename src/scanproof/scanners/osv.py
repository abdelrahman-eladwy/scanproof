"""OSV-Scanner JSON report (`osv-scanner scan --format json`), tested with osv-scanner 2.7.

  results[].source.path         a lockfile / manifest that HAD vulnerable packages
  results[].packages[].groups   one group per distinct vulnerability, with max_severity (CVSS)

OSV-Scanner lists only sources with vulnerabilities, so it does not say which lockfiles it read:
scope is unknown (a clean scan prints `{"results": []}`), and `required_paths` is UNKNOWN.
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by


def _band(score: Any) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    return "LOW" if value > 0 else "UNKNOWN"


class OsvScannerAdapter(ScannerAdapter):
    tool = "osv-scanner"
    scan_type = ScanType.DEPENDENCY

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            return "Not an OSV-Scanner report: missing 'results' list"
        for r in data["results"]:
            if not isinstance(r, dict) or not isinstance(r.get("packages", []), list):
                return "OSV-Scanner result without a packages list"
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        severities = [
            _band(g.get("max_severity"))
            for r in data["results"]
            for p in (r.get("packages") or [])
            for g in (p.get("groups") or [])
        ]
        return {
            "scanner_name": "osv-scanner",
            "scanner_errors": None,
            "results_reported": True,
            "findings": FindingsSummary(total=len(severities), by_severity=count_by(severities)),
        }
