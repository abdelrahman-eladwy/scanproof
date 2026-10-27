"""OWASP ZAP JSON report (`traditional-json` template, e.g. `zap-baseline.py -J`), tested with
ZAP 2.17.

  @version                          tool version
  site[].@name                      the target URL(s) scanned (target_url_must_match)
  site[].alerts[].riskcode          0 informational, 1 low, 2 medium, 3 high
  insights[insight.endpoint.total]  endpoints tested (minimum_endpoints); ZAP 2.16+ only
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScanScope, ScanTarget, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by

_RISK = {"0": "INFORMATIONAL", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}


class ZapAdapter(ScannerAdapter):
    tool = "zap"
    scan_type = ScanType.DAST

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict) or data.get("@programName") not in ("ZAP", "OWASP ZAP"):
            return "Not a ZAP JSON report: @programName is not ZAP"
        if not isinstance(data.get("site"), list):
            return "ZAP report needs a 'site' list"
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        sites = [s for s in data["site"] if isinstance(s, dict)]
        risks = [
            _RISK.get(str(a.get("riskcode")), "UNKNOWN")
            for s in sites
            for a in (s.get("alerts") or [])
            if isinstance(a, dict)
        ]
        endpoints = None
        for i in data.get("insights") or []:
            if isinstance(i, dict) and i.get("key") == "insight.endpoint.total":
                try:
                    endpoints = (endpoints or 0) + int(i.get("statistic"))
                except (TypeError, ValueError):
                    endpoints = None
                    break
        urls = [str(s.get("@name")) for s in sites if s.get("@name")]
        return {
            "tool_version": data.get("@version") if isinstance(data.get("@version"), str) else None,
            "scanner_name": "zap",
            "scanner_errors": None,
            "results_reported": True,
            "scope": ScanScope(endpoints=endpoints),
            "findings": FindingsSummary(total=len(risks), by_severity=count_by(risks)),
            "target": ScanTarget(urls=urls or None, artifact_type="web_application"),
        }
