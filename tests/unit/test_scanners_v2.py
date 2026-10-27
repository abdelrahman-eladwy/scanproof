"""Gitleaks, Grype, OSV-Scanner, Snyk, Kubescape, ZAP and Nuclei adapters against real output
(generated in .github/workflows/fixtures.yml; Snyk from DefectDojo's test data), and the DAST
checks target_url_must_match / minimum_endpoints."""

from __future__ import annotations

import json

import pytest

from scanproof.evidence.models import ScanEvidence, ScanScope, ScanTarget, ScanType
from scanproof.policy.engine import Outcome, _min_endpoints, _target_url
from scanproof.policy.models import Checks
from scanproof.scanners import get_adapter
from tests.conftest import FIXTURES

ALPINE = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"


def parse(tool: str, path: str) -> ScanEvidence:
    ev = get_adapter(tool).parse((FIXTURES / path).read_bytes())
    assert ev.parseable, ev.parse_error
    return ev


def test_gitleaks_redacted_finding_and_clean_run() -> None:
    leak = parse("gitleaks", "gitleaks/gitleaks-leak.json")
    assert leak.scan_type is ScanType.SECRETS and leak.findings.total == 1
    assert "REDACTED" in (FIXTURES / "gitleaks/gitleaks-leak.json").read_text()
    clean = parse("gitleaks", "gitleaks/gitleaks-clean.json")
    assert clean.findings.total == 0 and clean.scope is None  # gitleaks does not report scope


def test_grype_binds_to_the_image_digest() -> None:
    ev = parse("grype", "grype/grype-alpine.json")
    assert ev.scan_type is ScanType.CONTAINER and ev.tool_version == "0.121.0"
    assert ALPINE in ev.target.digests()
    assert ev.findings.total == 6


def test_grype_severity_bands() -> None:
    ev = parse("grype", "grype/grype-python-trimmed.json")
    assert set(ev.findings.by_severity) <= {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "NEGLIGIBLE",
        "UNKNOWN",
    }
    assert ev.findings.total <= 30


def test_osv_scanner_groups_and_unknown_scope() -> None:
    ev = parse("osv-scanner", "osv/osv-node.json")
    assert ev.scan_type is ScanType.DEPENDENCY and ev.findings.total >= 1
    assert ev.scope is None  # OSV lists only sources that had vulnerabilities
    clean = get_adapter("osv-scanner").parse(b'{"results": []}')
    assert clean.parseable and clean.findings.total == 0


@pytest.mark.parametrize(
    ("path", "scan_type", "projects", "total"),
    [
        ("snyk/single_project_one_vuln.json", ScanType.DEPENDENCY, 1, 1),
        ("snyk/single_project_no_vulns.json", ScanType.DEPENDENCY, 1, 0),
        ("snyk/all-projects_many_vulns.json", ScanType.DEPENDENCY, 3, None),
        ("snyk/snykcontainer_issue_epss.json", ScanType.CONTAINER, 1, None),
    ],
)
def test_snyk_projects(path, scan_type, projects, total) -> None:
    ev = parse("snyk", path)
    assert ev.scan_type is scan_type and ev.scope.files_scanned == projects
    if total is not None:
        assert ev.findings.total == total
    raw = json.loads((FIXTURES / path).read_text())
    deps = sum(p["dependencyCount"] for p in (raw if isinstance(raw, list) else [raw]))
    assert ev.scope.components == deps


def test_kubescape_resources_and_failed_controls() -> None:
    ev = parse("kubescape", "kubescape/kubescape.json")
    assert ev.scan_type is ScanType.IAC and ev.tool_version == "v3.0.46"
    assert ev.scope.resources == 2 and ev.scope.scanned_paths == ["deployment.yaml"]
    assert ev.findings.by_severity == {"HIGH": 9, "LOW": 6, "MEDIUM": 9}


def test_zap_targets_endpoints_and_risks() -> None:
    ev = parse("zap", "zap/zap-baseline.json")
    assert ev.scan_type is ScanType.DAST and ev.tool_version == "2.17.0"
    assert ev.target.urls == ["http://target"]
    assert ev.scope.endpoints == 2
    assert ev.findings.total == 10 and "MEDIUM" in ev.findings.by_severity


@pytest.mark.parametrize("path", ["nuclei/nuclei.jsonl", "nuclei/nuclei-export.json"])
def test_nuclei_jsonl_and_export(path) -> None:
    ev = parse("nuclei", path)
    assert ev.findings.total == 2 and ev.findings.by_severity == {"INFO": 2}
    assert ev.target.urls == ["http://target"]


def test_nuclei_empty_export_is_valid_but_targetless() -> None:
    ev = parse("nuclei", "nuclei/nuclei-empty-export.json")
    assert ev.findings.total == 0 and ev.target.urls is None
    assert get_adapter("nuclei").parse(b"").parseable is False  # empty -jsonl: can't tell


@pytest.mark.parametrize(
    ("tool", "raw"),
    [
        ("gitleaks", b'{"RuleID": "x"}'),
        ("gitleaks", b'[{"Description": "no rule"}]'),
        ("grype", b'{"descriptor": {"name": "trivy"}, "matches": [], "source": {}}'),
        ("osv-scanner", b'{"results": "x"}'),
        ("snyk", b"[]"),
        ("snyk", b'{"vulnerabilities": []}'),
        ("kubescape", b'{"results": []}'),
        ("zap", b'{"@programName": "Burp", "site": []}'),
        ("nuclei", b'[{"no": "template"}]'),
        ("nuclei", b'{"template-id": "x"}'),
    ],
)
def test_foreign_documents_are_not_accepted(tool, raw) -> None:
    assert get_adapter(tool).parse(raw).parseable is False


# ---------------------------------------------------------------- DAST checks


def dast(urls, endpoints=None) -> ScanEvidence:
    return ScanEvidence(
        tool="zap",
        scan_type=ScanType.DAST,
        present=True,
        parseable=True,
        target=ScanTarget(urls=urls),
        scope=ScanScope(endpoints=endpoints),
    )


@pytest.mark.parametrize(
    ("scanned", "expected", "outcome"),
    [
        (["https://app.example.com"], "https://app.example.com", Outcome.PASS),
        (["https://app.example.com/"], "https://app.example.com", Outcome.PASS),
        (["https://APP.example.com:443/shop"], "https://app.example.com/shop", Outcome.PASS),
        (["https://app.example.com/shop/cart"], "https://app.example.com/shop", Outcome.PASS),
        (["https://app.example.com/shopping"], "https://app.example.com/shop", Outcome.FAIL),
        (["https://app.example.com"], "https://app.example.com/shop", Outcome.FAIL),
        (["http://app.example.com"], "https://app.example.com", Outcome.FAIL),
        (["https://app.example.com:8443"], "https://app.example.com", Outcome.FAIL),
        (["https://staging.example.com"], "https://app.example.com", Outcome.FAIL),
        (["https://app.example.com.evil.net"], "https://app.example.com", Outcome.FAIL),
        (["not a url", "https://app.example.com"], "https://app.example.com", Outcome.PASS),
        (None, "https://app.example.com", Outcome.UNKNOWN),
    ],
)
def test_target_url(scanned, expected, outcome) -> None:
    assert _target_url(dast(scanned), expected).outcome is outcome


@pytest.mark.parametrize(
    ("endpoints", "outcome"), [(None, Outcome.UNKNOWN), (1, Outcome.FAIL), (2, Outcome.PASS)]
)
def test_minimum_endpoints(endpoints, outcome) -> None:
    assert _min_endpoints(dast(["http://x"], endpoints), 2).outcome is outcome


def test_target_url_from_env_and_validation(monkeypatch) -> None:
    monkeypatch.setenv("DEPLOY_URL", "https://app.example.com")
    assert Checks(target_url_must_match="${DEPLOY_URL}").target_url_must_match == (
        "https://app.example.com"
    )
    monkeypatch.delenv("DEPLOY_URL")
    with pytest.raises(ValueError, match="not set"):
        Checks(target_url_must_match="${DEPLOY_URL}")
    with pytest.raises(ValueError, match="http"):
        Checks(target_url_must_match="ftp://x")


@pytest.mark.parametrize(
    ("score", "band"),
    [
        ("9.8", "CRITICAL"),
        ("9.0", "CRITICAL"),
        ("7.5", "HIGH"),
        ("5.3", "MEDIUM"),
        ("3.1", "LOW"),
        ("0", "UNKNOWN"),
        ("", "UNKNOWN"),
        (None, "UNKNOWN"),
        ("n/a", "UNKNOWN"),
    ],
)
def test_osv_cvss_bands(score, band) -> None:
    from scanproof.scanners.osv import _band

    assert _band(score) == band


def test_dast_end_to_end_on_github(mock_api, sleeps) -> None:
    """A real ZAP baseline report in a run artifact, gated on the deployment URL."""
    from scanproof.connectors.github import GitHubConnector
    from scanproof.policy.engine import Decision
    from scanproof.policy.models import Policy
    from scanproof.verification import verify_pipeline
    from tests.fake_github import API, REPO, RUN, FakeGitHub

    gh = FakeGitHub(mock_api)
    gh.job(1, "dast")
    gh.artifact(10, "zap", {"zap.json": (FIXTURES / "zap/zap-baseline.json").read_bytes()})
    gh.install()

    def policy(url: str) -> Policy:
        return Policy.model_validate(
            {
                "apiVersion": "scanproof.dev/v1alpha1",
                "kind": "PipelineAssurancePolicy",
                "project": {"provider": "github", "id": REPO},
                "requirements": [
                    {
                        "id": "DAST",
                        "tool": "zap",
                        "job_name": "dast",
                        "artifact_name": "zap",
                        "report_path": "zap.json",
                        "checks": {"target_url_must_match": url, "minimum_endpoints": 1},
                    }
                ],
            }
        )

    with GitHubConnector(API, "t", sleep=sleeps.append) as c:
        ok = verify_pipeline(
            c, policy("http://target"), instance_url=API, project=REPO, pipeline_id=RUN
        )
        staging = verify_pipeline(
            c, policy("https://app.example.com"), instance_url=API, project=REPO, pipeline_id=RUN
        )
    assert ok.decision is Decision.VERIFIED
    assert staging.decision is Decision.BLOCKED
    assert [c.code for c in staging.requirements[0].checks if c.outcome.value == "FAIL"] == [
        "TARGET_MISMATCH"
    ]
