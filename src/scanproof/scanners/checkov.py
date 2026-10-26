"""Checkov native JSON adapter (`checkov -o json`). Tested against Checkov 3.3.30 (terraform).

Checkov writes one object per framework, or a list of them when several frameworks ran.

Mapping (all frameworks combined):
  summary.checkov_version              tool_version
  summary.parsing_errors / results.parsing_errors   scanner errors: files Checkov could not
                                       parse were silently not checked, which is the IaC
                                       equivalent of an unscanned file
  summary.resource_count               scope.resources (resources actually evaluated)
  results.failed_checks[]              findings; severity needs a Prisma Cloud API key and is
                                       usually null -> UNKNOWN
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScannerError, ScanScope, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by

MAX_PARSING_ERRORS = 100_000


class CheckovAdapter(ScannerAdapter):
    tool = "checkov"
    scan_type = ScanType.IAC

    def shape_problem(self, data: Any) -> str | None:
        reports = data if isinstance(data, list) else [data]
        if not reports or not all(isinstance(r, dict) for r in reports):
            return "Checkov report must be an object or a list of objects"
        for r in reports:
            if "check_type" not in r or not isinstance(r.get("summary"), dict):
                return "Not a Checkov JSON report: missing check_type or summary"
        return None

    def extract(self, data: Any) -> dict[str, Any]:
        reports: list[dict[str, Any]] = data if isinstance(data, list) else [data]
        errors: list[ScannerError] = []
        resources = 0
        severities: list[str] = []
        versions: set[str] = set()
        frameworks: list[str] = []
        for report in reports:
            summary = report["summary"]
            results = report.get("results") or {}
            frameworks.append(str(report["check_type"]))
            if summary.get("checkov_version"):
                versions.add(str(summary["checkov_version"]))
            resources += int(summary.get("resource_count") or 0)
            listed = [str(p) for p in results.get("parsing_errors") or []]
            count = max(int(summary.get("parsing_errors") or 0), len(listed))
            if not 0 <= count <= MAX_PARSING_ERRORS:
                # Found by fuzzing: an absurd count made us allocate one entry per error until
                # memory ran out. A report claiming this many is malformed, not evidence.
                raise ValueError(f"implausible parsing_errors count: {count}")
            for i in range(count):
                path = listed[i] if i < len(listed) else None
                errors.append(
                    ScannerError(
                        level="error",
                        type="parsing_error",
                        message=f"{report['check_type']}: file could not be parsed",
                        path=path,
                    )
                )
            for check in results.get("failed_checks") or []:
                severities.append(str(check.get("severity") or "UNKNOWN").upper())
        return {
            "tool_version": ", ".join(sorted(versions)) or None,
            "scanner_name": "checkov",
            "scanner_errors": errors,
            "scope": ScanScope(resources=resources, scanned_paths=None),
            "results_reported": True,
            "findings": FindingsSummary(total=len(severities), by_severity=count_by(severities)),
        }
