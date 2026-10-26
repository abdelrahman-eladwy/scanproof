"""Scanner adapter registry. Adding a tool = one new module + one line here."""

from __future__ import annotations

from scanproof.scanners.base import ScannerAdapter
from scanproof.scanners.checkov import CheckovAdapter
from scanproof.scanners.cyclonedx import CycloneDxAdapter
from scanproof.scanners.fortify import FortifyAdapter
from scanproof.scanners.gitlab_report import (
    GitLabContainerScanningAdapter,
    GitLabDependencyScanningAdapter,
    GitLabSastAdapter,
    GitLabSecretDetectionAdapter,
)
from scanproof.scanners.sarif import SarifAdapter
from scanproof.scanners.semgrep import SemgrepAdapter
from scanproof.scanners.sonatype import SonatypeIqAdapter
from scanproof.scanners.trivy import TrivyAdapter

ADAPTERS: dict[str, ScannerAdapter] = {
    a.tool: a
    for a in (
        SemgrepAdapter(),
        TrivyAdapter(),
        GitLabSastAdapter(),
        GitLabContainerScanningAdapter(),
        SarifAdapter(),
        CycloneDxAdapter(),
        GitLabDependencyScanningAdapter(),
        GitLabSecretDetectionAdapter(),
        CheckovAdapter(),
        FortifyAdapter(),
        SonatypeIqAdapter(),
    )
}


def get_adapter(tool: str) -> ScannerAdapter:
    try:
        return ADAPTERS[tool.lower()]
    except KeyError:
        supported = ", ".join(sorted(ADAPTERS))
        raise KeyError(f"Unsupported tool {tool!r}. Supported: {supported}") from None


__all__ = ["ADAPTERS", "ScannerAdapter", "get_adapter"]
