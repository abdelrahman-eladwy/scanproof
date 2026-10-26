"""Trivy JSON report adapter (`trivy image --format json`).

Relevant fields (tested against Trivy 0.76.x, SchemaVersion 2):
  Trivy.Version                      tool version
  ArtifactName, ArtifactType         what was scanned (e.g. container_image)
  Metadata.ImageID / RepoDigests     binds the report to an exact image
  Results[]                          one per target; absent when Trivy found nothing to scan
  Results[].Vulnerabilities[]        findings with Severity

Trivy's JSON has no field for the scanner's own errors, so `scanner_errors` is None
(unknown) rather than an empty list.
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScanScope, ScanTarget, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by

SUPPORTED_SCHEMA_VERSIONS = {2}


class TrivyAdapter(ScannerAdapter):
    tool = "trivy"
    scan_type = ScanType.CONTAINER

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict):
            return "Trivy report must be a JSON object"
        if "SchemaVersion" not in data or "ArtifactName" not in data:
            return "Not a Trivy JSON report: missing SchemaVersion or ArtifactName"
        if data["SchemaVersion"] not in SUPPORTED_SCHEMA_VERSIONS:
            return f"Unsupported Trivy SchemaVersion {data['SchemaVersion']!r}"
        if "Results" in data and not isinstance(data["Results"], list):
            return "Trivy 'Results' must be a list"
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        meta = data.get("Metadata") or {}
        target = ScanTarget(
            artifact_name=data.get("ArtifactName"),
            artifact_type=data.get("ArtifactType"),
            image_id=meta.get("ImageID"),
            repo_digests=_str_list(meta.get("RepoDigests")),
            repo_tags=_str_list(meta.get("RepoTags")),
        )

        results = data.get("Results")
        scope = None
        findings = None
        if isinstance(results, list):
            scope = ScanScope(scanned_paths=[str(r.get("Target")) for r in results])
            severities = [
                str(v.get("Severity", "UNKNOWN")).upper()
                for r in results
                for v in (r.get("Vulnerabilities") or [])
            ]
            findings = FindingsSummary(total=len(severities), by_severity=count_by(severities))

        trivy_meta = data.get("Trivy")
        version = trivy_meta.get("Version") if isinstance(trivy_meta, dict) else None
        return {
            "tool_version": version,
            "scanner_errors": None,
            "scope": scope,
            "results_reported": isinstance(results, list),
            "findings": findings,
            "target": target,
        }


def _str_list(value: Any) -> list[str] | None:
    return [str(v) for v in value] if isinstance(value, list) else None
