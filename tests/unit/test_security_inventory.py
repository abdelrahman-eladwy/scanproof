"""Guard the published CLI/provider/adapter inventory against accidental drift.

This is a documentation-consistency test, not a security proof: the separate
adversarial and live tests provide behavioral evidence for each invariant.
It runs against both source and installed ScanProof; the packaged CLI test
environment intentionally copies tests without repository documentation.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import get_args

from typer.main import get_command

from scanproof.cli import app
from scanproof.policy.models import ProjectRef
from scanproof.scanners import ADAPTERS

CLI_COMMANDS = {
    "inspect",
    "evidence",
    "attestation",
    "validate",
    "verify",
    "verify-release",
}
PROVIDERS = {"gitlab", "github", "azure-devops", "jenkins", "bitbucket"}
ADAPTER_TOOLS = {
    "semgrep",
    "trivy",
    "gitlab-sast",
    "gitlab-container-scanning",
    "sarif",
    "cyclonedx",
    "gitlab-dependency-scanning",
    "gitlab-secret-detection",
    "checkov",
    "fortify",
    "sonatype-iq",
    "bitbucket-code-insights",
    "gitleaks",
    "grype",
    "osv-scanner",
    "snyk",
    "kubescape",
    "zap",
    "nuclei",
}
DOC = Path(__file__).resolve().parents[2] / "docs/development/security-traceability.md"


def test_inventory_matches_runtime_interfaces() -> None:
    assert set(get_command(app).commands) == CLI_COMMANDS
    assert set(get_args(ProjectRef.model_fields["provider"].annotation)) == PROVIDERS
    assert set(ADAPTERS) == ADAPTER_TOOLS


def test_source_document_matches_inventory_and_references_real_tests() -> None:
    # The wheel/Docker validation copies only tests, examples and pyproject;
    # the runtime registry assertion above still executes in those jobs.
    if os.environ.get("SCANPROOF_TEST_INSTALLED") == "1":
        return

    doc = DOC.read_text(encoding="utf-8")
    for title, expected in (
        ("CLI command inventory", CLI_COMMANDS),
        ("Provider ID inventory", PROVIDERS),
        ("Adapter tool ID inventory", ADAPTER_TOOLS),
    ):
        match = re.search(rf"^\*\*{re.escape(title)}:\*\* (.+)$", doc, re.MULTILINE)
        assert match is not None, f"Missing {title} in traceability document"
        assert set(re.findall(r"`([a-z0-9-]+)`", match.group(1))) == expected, title

    assert set(re.findall(r"\*\*(INV-\d{2})\*\*", doc)) == {f"INV-{n:02d}" for n in range(1, 8)}
    referenced_tests = set(re.findall(r"`(tests/unit/test_[a-z0-9_]+\.py)`", doc))
    assert len(referenced_tests) >= 7
    for path in referenced_tests:
        assert (DOC.parents[2] / path).is_file(), f"Broken regression reference: {path}"
