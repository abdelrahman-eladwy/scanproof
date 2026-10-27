"""Kubescape JSON report (`kubescape scan <path|cluster> --format json`), tested with v3.0.46.

metadata.scanMetadata.kubescapeVersion   tool version
resources[]                              every resource evaluated (scope, minimum_resources)
resources[].source.relativePath          manifest file
results[].controls[]                     per resource: status passed / failed / skipped
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScanScope, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by


class KubescapeAdapter(ScannerAdapter):
    tool = "kubescape"
    scan_type = ScanType.IAC

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict):
            return "Kubescape report must be a JSON object"
        if not isinstance(data.get("summaryDetails"), dict) or not isinstance(
            data.get("results"), list
        ):
            return "Not a Kubescape report: missing summaryDetails or results"
        if not isinstance(data.get("resources", []), list):
            return "Kubescape 'resources' must be a list"
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        resources = [r for r in data.get("resources") or [] if isinstance(r, dict)]
        files = sorted(
            {
                str((r.get("source") or {}).get("relativePath"))
                for r in resources
                if isinstance(r.get("source"), dict) and (r.get("source") or {}).get("relativePath")
            }
        )
        failed = [
            str(c.get("severity") or "UNKNOWN").upper()
            for r in data["results"]
            if isinstance(r, dict)
            for c in (r.get("controls") or [])
            if isinstance(c, dict) and (c.get("status") or {}).get("status") == "failed"
        ]
        meta = ((data.get("metadata") or {}).get("scanMetadata")) or {}
        return {
            "tool_version": meta.get("kubescapeVersion") if isinstance(meta, dict) else None,
            "scanner_name": "kubescape",
            "scanner_errors": None,
            "results_reported": True,
            "scope": ScanScope(
                resources=len(resources),
                scanned_paths=files or None,
                files_scanned=len(files) if files else None,
            ),
            "findings": FindingsSummary(total=len(failed), by_severity=count_by(failed)),
        }
