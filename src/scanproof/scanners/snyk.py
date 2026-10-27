"""Snyk Open Source / Container JSON (`snyk test --json`, `snyk container test --json`).

One project is an object; `--all-projects` gives a list. Fields used:
  vulnerabilities[]          one entry per vulnerable path (deduplicated by id + package)
  dependencyCount            dependencies Snyk evaluated (scope)
  displayTargetFile / path   what was scanned
  docker                     present for container scans
Snyk Code output is SARIF: use the `sarif` tool with expected_scanner: SnykCode.
Fixtures are DefectDojo's (BSD-3): Snyk needs an account to run.
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScanScope, ScanTarget, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by


class SnykAdapter(ScannerAdapter):
    tool = "snyk"
    scan_type = ScanType.DEPENDENCY

    def shape_problem(self, data: Any) -> str | None:
        projects = data if isinstance(data, list) else [data]
        if not projects:
            return "Snyk report has no projects"
        for p in projects:
            if not isinstance(p, dict) or not isinstance(p.get("vulnerabilities"), list):
                return "Not a Snyk test report: missing 'vulnerabilities' list"
            if "ok" not in p:
                return "Not a Snyk test report: missing 'ok'"
        return None

    def extract(self, data: Any) -> dict[str, Any]:
        projects = data if isinstance(data, list) else [data]
        severities, paths, deps = [], [], 0
        container = False
        for p in projects:
            seen: set[tuple[str, str, str]] = set()
            for v in p["vulnerabilities"]:
                if not isinstance(v, dict):
                    continue
                key = (str(v.get("id")), str(v.get("packageName")), str(v.get("version")))
                if key not in seen:
                    seen.add(key)
                    severities.append(str(v.get("severity") or "unknown").upper())
            paths.append(str(p.get("displayTargetFile") or p.get("path") or p.get("projectName")))
            count = p.get("dependencyCount")
            deps += count if isinstance(count, int) and count >= 0 else 0
            container = container or p.get("docker") is not None
        target = None
        if container and isinstance(projects[0].get("path"), str):
            target = ScanTarget(artifact_name=projects[0]["path"], artifact_type="container_image")
        return {
            "scanner_name": "snyk",
            "scan_type": ScanType.CONTAINER if container else ScanType.DEPENDENCY,
            "scanner_errors": None,
            "results_reported": True,
            "scope": ScanScope(scanned_paths=paths, files_scanned=len(paths), components=deps),
            "findings": FindingsSummary(total=len(severities), by_severity=count_by(severities)),
            "target": target,
        }
