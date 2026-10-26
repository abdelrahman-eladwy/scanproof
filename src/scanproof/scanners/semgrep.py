"""Semgrep JSON report adapter (`semgrep scan --json`).

Relevant fields (tested against Semgrep 1.181.x):
  version             tool version
  results[]           findings; extra.severity is ERROR / WARNING / INFO (or newer levels)
  errors[]            the scanner's own problems: {code, level, type, message, path}
  paths.scanned[]     files actually scanned; paths.skipped[] only with --verbose
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScannerError, ScanScope, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by


class SemgrepAdapter(ScannerAdapter):
    tool = "semgrep"
    scan_type = ScanType.SAST

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict):
            return "Semgrep report must be a JSON object"
        missing = [k for k in ("results", "errors") if k not in data]
        if missing:
            return f"Not a Semgrep report: missing {', '.join(missing)}"
        if not isinstance(data["results"], list) or not isinstance(data["errors"], list):
            return "Semgrep 'results' and 'errors' must be lists"
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        errors = [
            ScannerError(
                level=e.get("level"),
                type=e.get("type"),
                message=str(e.get("message", "")).strip() or "(no message)",
                path=e.get("path"),
            )
            for e in data["errors"]
            if isinstance(e, dict)
        ]

        paths = data.get("paths")
        scope = None
        if isinstance(paths, dict) and isinstance(paths.get("scanned"), list):
            scanned = [str(p) for p in paths["scanned"]]
            skipped_raw = paths.get("skipped")
            skipped = (
                [str(s.get("path", s)) if isinstance(s, dict) else str(s) for s in skipped_raw]
                if isinstance(skipped_raw, list)
                else None
            )
            scope = ScanScope(
                files_scanned=len(scanned), scanned_paths=scanned, skipped_paths=skipped
            )

        severities = [
            str((r.get("extra") or {}).get("severity", "UNKNOWN")).upper() for r in data["results"]
        ]
        return {
            "tool_version": data.get("version"),
            "scanner_errors": errors,
            "scope": scope,
            "results_reported": True,
            "findings": FindingsSummary(total=len(severities), by_severity=count_by(severities)),
        }
