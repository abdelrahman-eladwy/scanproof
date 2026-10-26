"""Dependency, secrets and IaC scan types. Fixtures are REAL output from the fixtures workflow:
Checkov 3.3.30, Trivy 0.76.1 (filesystem), GitLab gemnasium:6 and secrets:7 analyzers."""

from __future__ import annotations

import json

import pytest

from scanproof.evidence.models import ScanType
from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.engine import Outcome, RequirementInput, evaluate_requirement
from scanproof.policy.models import Requirement
from scanproof.scanners import get_adapter
from tests.conftest import FIXTURES

SHA = "a" * 40


def raw(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def modified(name: str, fn) -> bytes:
    data = json.loads(raw(name))
    fn(data)
    return json.dumps(data).encode()


def checks_for(tool: str, evidence, **checks) -> dict:
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


# ---------------------------------------------------------------- dependency scanning


def test_trivy_filesystem_is_dependency_scan_with_lockfile_scope() -> None:
    ev = get_adapter("trivy").parse(raw("trivy/trivy-fs.json"))
    assert ev.scan_type is ScanType.DEPENDENCY
    assert ev.scope.scanned_paths == ["package-lock.json"]
    assert ev.scope.files_scanned == 1
    assert ev.findings.total == 7


def test_trivy_image_stays_container_scan() -> None:
    ev = get_adapter("trivy").parse(raw("trivy/trivy-python.json"))
    assert ev.scan_type is ScanType.CONTAINER
    assert ev.scope.files_scanned is None


def test_required_lockfile_was_scanned() -> None:
    ev = get_adapter("trivy").parse(raw("trivy/trivy-fs.json"))
    assert checks_for("trivy", ev, required_paths=["package-lock.json"])["required_paths"][0] is (
        Outcome.PASS
    )
    assert checks_for("trivy", ev, required_paths=["poetry.lock"])["required_paths"] == (
        Outcome.FAIL,
        "REQUIRED_PATH_NOT_SCANNED",
    )


def test_gitlab_dependency_scanning() -> None:
    ev = get_adapter("gitlab-dependency-scanning").parse(
        raw("gitlab-reports/gl-dependency-scanning-report.json")
    )
    assert ev.parseable and ev.scan_type is ScanType.DEPENDENCY
    assert ev.scanner_name == "gemnasium"
    assert ev.findings.by_severity == {"HIGH": 3, "MEDIUM": 3}
    assert ev.scope is None
    # schema 15.x lists no dependency files -> a lockfile requirement is UNKNOWN, never PASS
    assert (
        checks_for("gitlab-dependency-scanning", ev, required_paths=["package-lock.json"])[
            "required_paths"
        ][0]
        is Outcome.UNKNOWN
    )


# ---------------------------------------------------------------- secrets


def test_gitlab_secret_detection() -> None:
    ev = get_adapter("gitlab-secret-detection").parse(
        raw("gitlab-reports/gl-secret-detection-report.json")
    )
    assert ev.parseable and ev.scan_type is ScanType.SECRETS
    assert ev.scanner_name == "gitleaks"
    assert ev.findings.by_severity == {"CRITICAL": 1}
    assert ev.scanner_errors == []


def test_report_types_are_not_interchangeable() -> None:
    secrets_raw = raw("gitlab-reports/gl-secret-detection-report.json")
    for tool in ("gitlab-sast", "gitlab-dependency-scanning", "gitlab-container-scanning"):
        assert not get_adapter(tool).parse(secrets_raw).parseable


# ---------------------------------------------------------------- IaC


def test_checkov_report() -> None:
    ev = get_adapter("checkov").parse(raw("checkov/checkov.json"))
    assert ev.parseable and ev.scan_type is ScanType.IAC
    assert ev.tool_version == "3.3.30"
    assert ev.scope.resources == 3
    assert ev.scanner_errors == []
    assert ev.findings.total == 14


def test_checkov_parsing_errors_are_scanner_errors() -> None:
    def broken(d):
        d["summary"]["parsing_errors"] = 2
        d["results"]["parsing_errors"] = ["/broken.tf"]

    ev = get_adapter("checkov").parse(modified("checkov/checkov.json", broken))
    assert [e.path for e in ev.scanner_errors] == ["/broken.tf", None]
    assert checks_for("checkov", ev, scanner_errors_allowed=0)["scanner_errors"] == (
        Outcome.FAIL,
        "SCANNER_ERRORS",
    )


def test_checkov_multi_framework_list() -> None:
    one = json.loads(raw("checkov/checkov.json"))
    two = json.loads(raw("checkov/checkov.json"))
    two["check_type"] = "kubernetes"
    ev = get_adapter("checkov").parse(json.dumps([one, two]).encode())
    assert ev.scope.resources == 6 and ev.findings.total == 28


def test_minimum_resources() -> None:
    ev = get_adapter("checkov").parse(raw("checkov/checkov.json"))
    assert checks_for("checkov", ev, minimum_resources=1)["minimum_resources"][0] is Outcome.PASS
    assert checks_for("checkov", ev, minimum_resources=10)["minimum_resources"] == (
        Outcome.FAIL,
        "TOO_FEW_RESOURCES",
    )
    no_scope = ev.model_copy(update={"scope": None})
    assert checks_for("checkov", no_scope, minimum_resources=1)["minimum_resources"][0] is (
        Outcome.UNKNOWN
    )


@pytest.mark.parametrize(
    "data", [b"[]", b'{"check_type": "terraform"}', b'[{"summary": {}}]', b'"x"']
)
def test_invalid_checkov(data) -> None:
    assert not get_adapter("checkov").parse(data).parseable
