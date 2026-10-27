"""Grype JSON report (`grype <target> -o json`), tested with Grype 0.121.

  descriptor.version              tool version
  source.type / source.target     image (userInput, imageID, repoDigests, tags) or dir / sbom
  matches[].vulnerability         id, severity
  matches[].artifact              the vulnerable package

Grype binds image scans to repo digests, so `image_digest_must_match` works as with Trivy.
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import FindingsSummary, ScanTarget, ScanType
from scanproof.scanners.base import ScannerAdapter, count_by


class GrypeAdapter(ScannerAdapter):
    tool = "grype"
    scan_type = ScanType.CONTAINER

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict):
            return "Grype report must be a JSON object"
        descriptor = data.get("descriptor")
        if not isinstance(descriptor, dict) or descriptor.get("name") != "grype":
            return "Not a Grype report: descriptor.name is not 'grype'"
        if not isinstance(data.get("matches"), list) or not isinstance(data.get("source"), dict):
            return "Grype report needs 'matches' (list) and 'source' (object)"
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        source = data["source"]
        kind = str(source.get("type") or "")
        t = source.get("target")
        target = None
        if kind == "image" and isinstance(t, dict):
            target = ScanTarget(
                artifact_name=_str(t.get("userInput")),
                artifact_type="container_image",
                image_id=_str(t.get("imageID")),
                repo_digests=_strs(t.get("repoDigests")),
                repo_tags=_strs(t.get("tags")),
            )
        elif isinstance(t, str):
            target = ScanTarget(artifact_name=t, artifact_type=kind or None)
        seen: set[tuple[str, str, str]] = set()
        severities = []
        for m in data["matches"]:
            vuln, art = m.get("vulnerability") or {}, m.get("artifact") or {}
            key = (str(vuln.get("id")), str(art.get("name")), str(art.get("version")))
            if key not in seen:
                seen.add(key)
                severities.append(str(vuln.get("severity") or "Unknown").upper())
        return {
            "tool_version": _str(data["descriptor"].get("version")),
            "scanner_name": "grype",
            "scan_type": ScanType.CONTAINER if kind == "image" else ScanType.DEPENDENCY,
            "scanner_errors": None,
            "results_reported": True,
            "findings": FindingsSummary(total=len(severities), by_severity=count_by(severities)),
            "target": target,
        }


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _strs(value: Any) -> list[str] | None:
    return [str(v) for v in value] if isinstance(value, list) else None
