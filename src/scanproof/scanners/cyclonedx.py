"""CycloneDX JSON SBOM adapter.

Evidence that an SBOM was produced for the artifact being shipped. Tested against real
CycloneDX 1.7 output of Trivy 0.76.1 and Syft 1.55.0 for container images.

Mapping:
  metadata.tools                  scanner_name / tool_version (1.5+ object form and legacy list)
  components[] (recursive)        scope.components
  metadata.component              target; a digest is taken from the purl / bom-ref
                                  (pkg:oci/...@sha256:...) or a RepoDigest property
  vulnerabilities[]               findings ONLY when non-empty. Generators write an empty list
                                  when they did not scan for vulnerabilities, so [] is treated
                                  as unknown, not as "zero findings".
CycloneDX has no section for generator errors, so scanner errors are unknown.
"""

from __future__ import annotations

import re
from typing import Any

from scanproof.evidence.models import FindingsSummary, ScanScope, ScanTarget, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by

_DIGEST = re.compile(r"sha256(?::|%3A)([0-9a-f]{64})", re.IGNORECASE)


class CycloneDxAdapter(ScannerAdapter):
    tool = "cyclonedx"
    scan_type = ScanType.SBOM

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict):
            return "CycloneDX BOM must be a JSON object"
        if data.get("bomFormat") != "CycloneDX" or "specVersion" not in data:
            return "Not a CycloneDX JSON BOM: missing bomFormat=CycloneDX or specVersion"
        if "components" in data and not isinstance(data["components"], list):
            return "CycloneDX 'components' must be a list"
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        metadata = data.get("metadata") or {}
        tools = _tools(metadata.get("tools"))
        components = data.get("components")
        vulns = data.get("vulnerabilities")
        findings = None
        if isinstance(vulns, list) and vulns:
            findings = FindingsSummary(
                total=len(vulns), by_severity=count_by([_severity(v) for v in vulns])
            )
        return {
            "tool_version": ", ".join(f"{n} {v}".strip() for n, v in tools) or None,
            "scanner_name": ", ".join(n for n, _ in tools) or None,
            "scanner_errors": None,
            "scope": ScanScope(components=_count(components))
            if isinstance(components, list)
            else None,
            "results_reported": isinstance(components, list),
            "findings": findings,
            "target": _target(metadata.get("component")),
        }


def _tools(tools: Any) -> list[tuple[str, str]]:
    if isinstance(tools, dict):  # CycloneDX 1.5+: {"components": [...], "services": [...]}
        items = (tools.get("components") or []) + (tools.get("services") or [])
    elif isinstance(tools, list):  # legacy: [{"vendor", "name", "version"}]
        items = tools
    else:
        return []
    return [
        (str(t.get("name")), str(t.get("version") or ""))
        for t in items
        if isinstance(t, dict) and t.get("name")
    ]


def _count(components: Any) -> int:
    if not isinstance(components, list):
        return 0
    return sum(1 + _count(c.get("components")) for c in components if isinstance(c, dict))


def _severity(vuln: dict[str, Any]) -> str:
    ratings = vuln.get("ratings") or []
    for rating in ratings:
        if isinstance(rating, dict) and rating.get("severity"):
            return str(rating["severity"]).upper()
    return "UNKNOWN"


def _target(component: Any) -> ScanTarget | None:
    if not isinstance(component, dict):
        return None
    refs = [str(component.get("purl") or ""), str(component.get("bom-ref") or "")]
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and "repodigest" in str(prop.get("name", "")).lower():
            refs.append(str(prop.get("value", "")))
    digests = sorted({f"sha256:{m.group(1).lower()}" for r in refs for m in _DIGEST.finditer(r)})
    name = component.get("name")
    version = component.get("version")
    return ScanTarget(
        artifact_name=f"{name}:{version}" if name and version else name,
        artifact_type=component.get("type"),
        repo_digests=[f"{name}@{d}" for d in digests] or None,
    )
