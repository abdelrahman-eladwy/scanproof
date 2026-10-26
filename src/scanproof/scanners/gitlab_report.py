"""GitLab Security Report format adapters (gl-sast-report.json, gl-container-scanning-report.json).

These are what GitLab's own SAST and Container Scanning CI templates produce (any tier). Tested
against real output of registry.gitlab.com/security-products/semgrep:6 (report schema 15.2.4)
and container-scanning:8 (schema 15.1.1).

Relevant fields:
  version                    report schema version
  scan.type                  sast | container_scanning | ...
  scan.status                success | failure  - the analyzer's own verdict on its run
  scan.messages[]            optional {level: info|warn|fatal, value}
  scan.scanner / analyzer    underlying tool (e.g. semgrep, trivy) and GitLab wrapper versions
  vulnerabilities[]          findings; severity Critical|High|Medium|Low|Info|Unknown
  vulnerabilities[].location.image   container scanning: the scanned image reference

Limits of the format, reflected as unknowns rather than guesses:
  * No list of scanned files, so scope (minimum_scanned_files, required_paths) is unknown.
  * The image is recorded as given to the analyzer; a digest is only known when the pipeline
    scanned by digest (CS_IMAGE=registry/app@sha256:...), and only if there is at least one
    finding to carry the location.
"""

from __future__ import annotations

from typing import Any, ClassVar

from scanproof.evidence.models import FindingsSummary, ScannerError, ScanTarget, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by

_ERROR_LEVELS = {"warn", "warning", "error", "fatal"}


class _GitLabReportAdapter(ScannerAdapter):
    report_type: ClassVar[str]

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict):
            return "GitLab security report must be a JSON object"
        scan = data.get("scan")
        if "version" not in data or not isinstance(scan, dict) or "type" not in scan:
            return "Not a GitLab security report: missing version or scan.type"
        if not isinstance(data.get("vulnerabilities"), list):
            return "GitLab security report 'vulnerabilities' must be a list"
        if scan["type"] != self.report_type:
            return (
                f"GitLab report is scan.type '{scan['type']}', "
                f"requirement expects '{self.report_type}'"
            )
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        scan = data["scan"]
        return {
            "tool_version": _tool_version(scan),
            "scanner_name": (scan.get("scanner") or {}).get("id"),
            "scanner_errors": _scanner_errors(scan),
            "scope": None,  # the format does not list scanned files
            "results_reported": True,
            "findings": FindingsSummary(
                total=len(data["vulnerabilities"]),
                by_severity=count_by(
                    [str(v.get("severity", "Unknown")).upper() for v in data["vulnerabilities"]]
                ),
            ),
        }


class GitLabSastAdapter(_GitLabReportAdapter):
    tool = "gitlab-sast"
    scan_type = ScanType.SAST
    report_type = "sast"


class GitLabContainerScanningAdapter(_GitLabReportAdapter):
    tool = "gitlab-container-scanning"
    scan_type = ScanType.CONTAINER
    report_type = "container_scanning"

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        fields = super().extract(data)
        images = {
            str((v.get("location") or {}).get("image"))
            for v in data["vulnerabilities"]
            if (v.get("location") or {}).get("image")
        }
        if len(images) == 1:
            (image,) = images
            fields["target"] = ScanTarget(
                artifact_name=image,
                artifact_type="container_image",
                repo_digests=[image] if "@sha256:" in image else None,
            )
        elif len(images) > 1:
            # One report describing several images cannot be bound to one artifact.
            fields["target"] = ScanTarget(artifact_name=", ".join(sorted(images)))
        else:
            fields["target"] = None
        return fields


def _tool_version(scan: dict[str, Any]) -> str | None:
    scanner = scan.get("scanner") or {}
    analyzer = scan.get("analyzer") or {}
    parts = []
    if scanner.get("id") or scanner.get("version"):
        parts.append(f"{scanner.get('id', '?')} {scanner.get('version', '?')}")
    if analyzer.get("id") or analyzer.get("version"):
        parts.append(f"(GitLab analyzer {analyzer.get('id', '?')} {analyzer.get('version', '?')})")
    return " ".join(parts) or None


def _scanner_errors(scan: dict[str, Any]) -> list[ScannerError] | None:
    status = scan.get("status")
    if status is None:
        return None  # the analyzer did not say whether it succeeded
    errors = [
        ScannerError(
            level=str(m.get("level")), type="scan.message", message=str(m.get("value", ""))
        )
        for m in scan.get("messages") or []
        if isinstance(m, dict) and str(m.get("level", "")).lower() in _ERROR_LEVELS
    ]
    if status != "success":
        errors.insert(
            0,
            ScannerError(level="error", type="scan.status", message=f"scan.status is '{status}'"),
        )
    return errors


class GitLabDependencyScanningAdapter(_GitLabReportAdapter):
    """gl-dependency-scanning-report.json (tested: gemnasium:6, schema 15.2.2).

    Schema 15.x no longer lists dependency_files, so which lockfiles were read is unknown.
    """

    tool = "gitlab-dependency-scanning"
    scan_type = ScanType.DEPENDENCY
    report_type = "dependency_scanning"


class GitLabSecretDetectionAdapter(_GitLabReportAdapter):
    """gl-secret-detection-report.json (tested: secrets:7, which runs gitleaks 8.30.1)."""

    tool = "gitlab-secret-detection"
    scan_type = ScanType.SECRETS
    report_type = "secret_detection"
