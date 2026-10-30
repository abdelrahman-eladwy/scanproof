"""SARIF and CycloneDX adapters. Fixtures are REAL output (see tests/fixtures/README.md):
SARIF from Semgrep 1.181.1, Trivy 0.76.1, gitleaks 8.30.1 (redacted), Checkov 3.3.30;
CycloneDX 1.7 from Trivy 0.76.1 and Syft 1.55.0. Large ones trimmed by scripts/trim_report.py."""

from __future__ import annotations

import json

import pytest

from scanproof.evidence.models import ScanType
from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.engine import Outcome, RequirementInput, evaluate_requirement
from scanproof.policy.models import Requirement
from scanproof.scanners.cyclonedx import CycloneDxAdapter
from scanproof.scanners.sarif import SarifAdapter
from tests.conftest import FIXTURES

sarif = SarifAdapter()
cdx = CycloneDxAdapter()
PY_DIGEST = "sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"


def raw(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def modified(name: str, fn) -> bytes:
    data = json.loads(raw(name))
    fn(data)
    return json.dumps(data).encode()


# ---------------------------------------------------------------- SARIF


@pytest.mark.parametrize(
    ("name", "scanner", "total"),
    [
        ("sarif/semgrep.sarif", "Semgrep OSS", 6),
        ("sarif/trivy-image.sarif", "Trivy", 30),
        ("sarif/gitleaks.sarif", "gitleaks", 1),
        ("sarif/checkov.sarif", "Checkov", 14),
    ],
)
def test_real_sarif_logs(name, scanner, total) -> None:
    ev = sarif.parse(raw(name))
    assert ev.parseable and ev.scan_type is ScanType.OTHER
    assert ev.scanner_name == scanner
    assert ev.findings.total == total
    assert ev.results_reported is True


def test_sarif_level_falls_back_to_rule_default() -> None:
    """Semgrep's SARIF omits result.level; it must match Semgrep's native severities."""
    ev = sarif.parse(raw("sarif/semgrep.sarif"))
    assert ev.findings.by_severity == {"ERROR": 4, "WARNING": 2}


def test_sarif_without_rule_default_uses_warning() -> None:
    def strip(d):
        for rule in d["runs"][0]["tool"]["driver"]["rules"]:
            rule.pop("defaultConfiguration", None)

    ev = sarif.parse(modified("sarif/semgrep.sarif", strip))
    assert ev.findings.by_severity == {"WARNING": 6}


def test_sarif_errors_from_invocations() -> None:
    assert sarif.parse(raw("sarif/semgrep.sarif")).scanner_errors == []
    assert sarif.parse(raw("sarif/checkov.sarif")).scanner_errors is None  # no invocations

    def broken(d):
        d["runs"][0]["invocations"] = [
            {
                "executionSuccessful": False,
                "exitCode": 2,
                "toolExecutionNotifications": [
                    {
                        "level": "error",
                        "message": {"text": "parse failed"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}],
                    },
                    {"level": "note", "message": {"text": "fyi"}},
                    {"message": {"text": "default level is warning"}},
                ],
            }
        ]

    errors = sarif.parse(modified("sarif/semgrep.sarif", broken)).scanner_errors
    assert [(e.type, e.level) for e in errors] == [
        ("invocation", "error"),
        ("toolExecutionNotifications", "error"),
        ("toolExecutionNotifications", "warn"),
    ]
    assert errors[1].path == "a.py"
    assert "exit code 2" in errors[0].message


def test_sarif_scope_from_artifacts() -> None:
    assert sarif.parse(raw("sarif/semgrep.sarif")).scope is None

    def with_artifacts(d):
        d["runs"][0]["artifacts"] = [
            {"location": {"uri": "src/a.py"}},
            {"location": {"uri": "b.py"}},
        ]

    scope = sarif.parse(modified("sarif/semgrep.sarif", with_artifacts)).scope
    assert scope.files_scanned == 2 and scope.scanned_paths == ["src/a.py", "b.py"]


def test_trivy_sarif_binds_image_digest() -> None:
    ev = sarif.parse(raw("sarif/trivy-image.sarif"))
    assert ev.target.artifact_name == "python:3.12-slim"
    assert ev.target.digests() == {PY_DIGEST}


def test_sarif_results_missing_is_not_zero() -> None:
    ev = sarif.parse(modified("sarif/checkov.sarif", lambda d: d["runs"][0].pop("results")))
    assert ev.parseable and ev.results_reported is False


def test_multi_run_sarif_joins_scanners() -> None:
    semgrep = json.loads(raw("sarif/semgrep.sarif"))
    checkov = json.loads(raw("sarif/checkov.sarif"))
    semgrep["runs"].extend(checkov["runs"])
    ev = sarif.parse(json.dumps(semgrep).encode())
    assert ev.scanner_name == "Semgrep OSS, Checkov"
    assert ev.findings.total == 20


@pytest.mark.parametrize(
    "data",
    [
        b"[]",
        b'{"version": "1.0", "runs": [{"tool": {}}]}',
        b'{"version": "2.1.0", "runs": []}',
        b'{"version": "2.1.0", "runs": [{"results": []}]}',
    ],
)
def test_invalid_sarif(data) -> None:
    assert not sarif.parse(data).parseable


# ---------------------------------------------------------------- CycloneDX


def test_trivy_sbom() -> None:
    ev = cdx.parse(raw("cyclonedx/trivy-image.cdx.json"))
    assert ev.parseable and ev.scan_type is ScanType.SBOM
    assert ev.scanner_name == "trivy" and ev.tool_version == "trivy 0.76.1"
    assert ev.scope.components == 30
    assert ev.target.digests() == {PY_DIGEST}
    assert ev.findings is None  # Trivy wrote vulnerabilities: [] without scanning for them


def test_syft_sbom_has_no_digest() -> None:
    ev = cdx.parse(raw("cyclonedx/syft-alpine.cdx.json"))
    assert ev.scanner_name == "syft"
    assert ev.target.artifact_name == "alpine:3.20"
    assert ev.target.digests() == set()


def test_sbom_nested_components_and_legacy_tools() -> None:
    def legacy(d):
        d["metadata"]["tools"] = [{"vendor": "x", "name": "old-gen", "version": "1"}]
        d["components"] = [{"name": "a", "components": [{"name": "b"}, {"name": "c"}]}]
        d["vulnerabilities"] = [{"id": "CVE-1", "ratings": [{"severity": "high"}]}, {"id": "CVE-2"}]

    ev = cdx.parse(modified("cyclonedx/syft-alpine.cdx.json", legacy))
    assert ev.scanner_name == "old-gen"
    assert ev.scope.components == 3
    assert ev.findings.by_severity == {"HIGH": 1, "UNKNOWN": 1}


def test_sbom_without_components_is_unknown_scope() -> None:
    ev = cdx.parse(modified("cyclonedx/syft-alpine.cdx.json", lambda d: d.pop("components")))
    assert ev.parseable and ev.scope is None and ev.results_reported is False


@pytest.mark.parametrize(
    "data",
    [
        b"[]",
        b'{"bomFormat": "SPDX"}',
        b'{"bomFormat": "CycloneDX"}',
        b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": {}}',
    ],
)
def test_invalid_cyclonedx(data) -> None:
    assert not cdx.parse(data).parseable


# ---------------------------------------------------------------- new policy checks

SHA = "a" * 40


def _evaluate(tool: str, evidence, **checks):
    job = Job(id=1, name="scan", status=JobStatus.SUCCESS, commit_sha=SHA)
    inspected = InspectedJob(
        name="scan", stage="s", latest=job, attempt_ids=[1], commit_matches_pipeline=True
    )
    req = Requirement.model_validate(
        {"id": "R", "tool": tool, "job_name": "scan", "report_path": "r", "checks": checks}
    )
    res = evaluate_requirement(
        req,
        Pipeline(id=1, sha=SHA, status="success"),
        RequirementInput(job=inspected, evidence=evidence),
    )
    return {c.check: (c.outcome, c.code) for c in res.checks}


def test_expected_scanner() -> None:
    ev = sarif.parse(raw("sarif/checkov.sarif"))
    assert _evaluate("sarif", ev, expected_scanner="checkov")["expected_scanner"] == (
        Outcome.PASS,
        "SCANNER_MATCHES",
    )
    assert _evaluate("sarif", ev, expected_scanner="CodeQL")["expected_scanner"] == (
        Outcome.FAIL,
        "SCANNER_MISMATCH",
    )
    nameless = ev.model_copy(update={"scanner_name": None})
    assert (
        _evaluate("sarif", nameless, expected_scanner="x")["expected_scanner"][0] is Outcome.UNKNOWN
    )


def test_expected_scanner_rejects_mixed_runs() -> None:
    """A multi-tool SARIF must not satisfy a single expected scanner."""
    ev = sarif.parse(raw("sarif/semgrep.sarif")).model_copy(
        update={"scanner_name": "Semgrep OSS, Checkov"}
    )
    assert _evaluate("sarif", ev, expected_scanner="Checkov")["expected_scanner"][0] is Outcome.FAIL


def test_minimum_components_and_sbom_digest() -> None:
    ev = cdx.parse(raw("cyclonedx/trivy-image.cdx.json"))
    result = _evaluate("cyclonedx", ev, minimum_components=10, image_digest_must_match=PY_DIGEST)
    assert result["minimum_components"] == (Outcome.PASS, "SBOM_COMPONENTS_OK")
    assert result["image_digest_must_match"] == (Outcome.PASS, "IMAGE_DIGEST_MATCHES")
    assert _evaluate("cyclonedx", ev, minimum_components=100)["minimum_components"] == (
        Outcome.FAIL,
        "SBOM_TOO_SMALL",
    )
    no_scope = ev.model_copy(update={"scope": None})
    assert _evaluate("cyclonedx", no_scope, minimum_components=1)["minimum_components"][0] is (
        Outcome.UNKNOWN
    )


# ---------------------------------------------------------------- suppressed findings (#123)


def test_real_nosemgrep_suppression_is_counted_not_hidden() -> None:
    # Real Semgrep SARIF: two `print` matches, one silenced with `# nosemgrep`.
    ev = sarif.parse(raw("sarif/semgrep-nosem.sarif"))
    assert ev.findings.total == 1
    assert ev.findings.suppressed == 1


@pytest.mark.parametrize(
    "name", ["sarif/semgrep.sarif", "sarif/trivy-image.sarif", "sarif/checkov.sarif"]
)
def test_sarif_without_suppressions_reports_zero(name) -> None:
    assert sarif.parse(raw(name)).findings.suppressed == 0


@pytest.mark.parametrize(
    ("suppressions", "hidden"),
    [
        ([], False),  # SARIF: empty array = not suppressed
        ([{"kind": "inSource"}], True),
        ([{"kind": "external", "status": "underReview"}], True),
        ([{"kind": "external", "status": "accepted"}], True),
        ([{"kind": "inSource", "status": "rejected"}], False),
        ([{"status": "rejected"}, {"kind": "inSource"}], True),
        ("garbage", True),  # malformed: never counted as an ordinary finding
        (["garbage"], True),
    ],
)
def test_sarif_suppression_status_semantics(suppressions, hidden) -> None:
    def mark(data):
        data["runs"][0]["results"][0]["suppressions"] = suppressions
        return data

    ev = sarif.parse(modified("sarif/semgrep.sarif", mark))
    base = sarif.parse(raw("sarif/semgrep.sarif"))
    assert ev.findings.suppressed == (1 if hidden else 0)
    assert ev.findings.total == base.findings.total - (1 if hidden else 0)


def test_suppressed_findings_allowed_check() -> None:
    ev = sarif.parse(raw("sarif/semgrep-nosem.sarif"))
    check = "suppressed_findings_allowed"
    assert _evaluate("sarif", ev, suppressed_findings_allowed=1)[check] == (
        Outcome.PASS,
        "SUPPRESSIONS_OK",
    )
    assert _evaluate("sarif", ev, suppressed_findings_allowed=0)[check] == (
        Outcome.FAIL,
        "SUPPRESSED_FINDINGS_EXCEEDED",
    )


def test_suppressed_findings_unknown_when_the_format_does_not_say() -> None:
    # Semgrep JSON does not report nosemgrep-silenced results: unknown, never a pass.
    from scanproof.scanners.semgrep import SemgrepAdapter

    ev = SemgrepAdapter().parse(raw("semgrep/semgrep-findings.json"))
    assert ev.findings.suppressed is None
    assert _evaluate("semgrep", ev, suppressed_findings_allowed=5)[
        "suppressed_findings_allowed"
    ] == (Outcome.UNKNOWN, "SUPPRESSIONS_UNKNOWN")
