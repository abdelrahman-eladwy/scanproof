"""Fortify (FPR/FVDL) and Sonatype IQ adapters - EXPERIMENTAL.

Fixtures are real files from DefectDojo's test suite (BSD-3-Clause, see
tests/fixtures/LICENSE-DefectDojo.md): an FPR produced by Fortify SCA 24.2.0 and IQ Server raw
application reports. Expected Fortify priorities are cross-checked against DefectDojo's own
assertions for the same file."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from scanproof.evidence.models import ScanType
from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.engine import Outcome, RequirementInput, evaluate_requirement
from scanproof.policy.models import Requirement
from scanproof.scanners.fortify import FortifyAdapter
from scanproof.scanners.sonatype import SonatypeIqAdapter
from tests.conftest import FIXTURES

fortify = FortifyAdapter()
sonatype = SonatypeIqAdapter()
FPR = (FIXTURES / "fortify/hello_world.fpr").read_bytes()


def fpr_members() -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(FPR)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


def make_fpr(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


# ---------------------------------------------------------------- Fortify (real FPR)


def test_real_fpr() -> None:
    ev = fortify.parse(FPR)
    assert ev.parseable and ev.scan_type is ScanType.SAST
    assert ev.tool_version == "24.2.0.0150" and ev.scanner_name == "fortify-sca"
    assert ev.scanner_errors == []
    assert ev.scope.files_scanned == 3
    assert "src/main/java/hello/HelloWorld.java" in ev.scope.scanned_paths


def test_priorities_match_fortify_formula_and_defectdojo() -> None:
    """DefectDojo asserts Low (720E3A66) and High (9C5BD1B5) for this file; one issue is
    suppressed in audit.xml and must not be counted."""
    ev = fortify.parse(FPR)
    assert ev.findings.total == 3
    assert ev.findings.by_severity == {"CRITICAL": 1, "HIGH": 1, "LOW": 1}
    assert ev.findings.suppressed == 1


def test_bare_fvdl_has_no_suppression_info() -> None:
    ev = fortify.parse(fpr_members()["audit.fvdl"])
    assert ev.parseable and ev.findings.total == 4 and ev.findings.suppressed == 0


def test_fortify_scan_errors() -> None:
    members = fpr_members()
    members["audit.fvdl"] = (
        members["audit.fvdl"]
        .replace(
            b"<Errors/>",
            b'<Errors><Error code="1101">Translation failed for Foo.java</Error></Errors>',
        )
        .replace(
            b"<Errors></Errors>",
            b'<Errors><Error code="1101">Translation failed for Foo.java</Error></Errors>',
        )
    )
    ev = fortify.parse(make_fpr(members))
    assert [(e.type, e.message) for e in ev.scanner_errors] == [
        ("fortify code 1101", "Translation failed for Foo.java")
    ]


def test_rule_without_metadata_is_unknown_priority() -> None:
    members = fpr_members()
    members["audit.fvdl"] = members["audit.fvdl"].replace(b'name="Impact"', b'name="X-Impact"')
    ev = fortify.parse(make_fpr(members))
    assert set(ev.findings.by_severity) == {"UNKNOWN"}


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"not xml, not zip", "Not a Fortify FPR"),
        (make_fpr({"other.txt": b"x"}), "no audit.fvdl"),
        (b"PK\x03\x04garbage", "not a valid zip"),
        (b"<FVDL><unclosed></FVDL>", "not well-formed"),
        (b"<NotFVDL/>", "Not a Fortify FVDL document"),
    ],
)
def test_invalid_fortify(data, reason) -> None:
    ev = fortify.parse(data)
    assert not ev.parseable and reason in ev.parse_error


BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>
<FVDL>&lol3;</FVDL>"""
XXE = b"""<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<FVDL>&xxe;</FVDL>"""


@pytest.mark.parametrize("payload", [BILLION_LAUGHS, XXE], ids=["billion-laughs", "xxe"])
def test_malicious_xml_is_refused(payload) -> None:
    for data in (payload, make_fpr({"audit.fvdl": payload})):
        ev = fortify.parse(data)
        assert not ev.parseable
        assert "refused unsafe XML" in ev.parse_error


def test_oversized_fvdl_member(monkeypatch) -> None:
    monkeypatch.setattr("scanproof.scanners.fortify.MAX_FVDL_BYTES", 1000)
    ev = fortify.parse(FPR)
    assert not ev.parseable and "limit" in ev.parse_error


def test_fortify_scope_supports_required_paths() -> None:
    sha = "a" * 40
    job = Job(id=1, name="fortify", status=JobStatus.SUCCESS, commit_sha=sha)
    inspected = InspectedJob(
        name="fortify", stage="s", latest=job, attempt_ids=[1], commit_matches_pipeline=True
    )
    req = Requirement.model_validate(
        {
            "id": "F",
            "tool": "fortify",
            "job_name": "fortify",
            "report_path": "scan.fpr",
            "checks": {
                "scanner_errors_allowed": 0,
                "required_paths": ["src/main/java/"],
                "minimum_scanned_files": 2,
            },
        }
    )
    res = evaluate_requirement(
        req,
        Pipeline(id=1, sha=sha, status="success"),
        RequirementInput(job=inspected, evidence=fortify.parse(FPR)),
    )
    assert res.outcome is Outcome.PASS


# ---------------------------------------------------------------- Sonatype IQ


@pytest.mark.parametrize(
    ("name", "total", "by_severity"),
    [
        ("two_vulns", 2, {"SEVERE": 2}),
        ("many_vulns", 6, {"CRITICAL": 2, "SEVERE": 4}),
        ("no_vuln", 0, {}),
    ],
)
def test_real_sonatype_reports(name, total, by_severity) -> None:
    ev = sonatype.parse((FIXTURES / f"sonatype/{name}.json").read_bytes())
    assert ev.parseable and ev.scan_type is ScanType.DEPENDENCY
    assert ev.findings.total == total and ev.findings.by_severity == by_severity
    assert ev.scope.components == 1011  # matchSummary.totalComponentCount, not len(components)
    assert ev.scanner_errors is None


def test_sonatype_waived_and_missing_summary() -> None:
    data = json.loads((FIXTURES / "sonatype/two_vulns.json").read_text())
    issues = data["components"][0]["securityData"]["securityIssues"]
    issues[0]["status"] = "Waived"
    data.pop("matchSummary")
    ev = sonatype.parse(json.dumps(data).encode())
    assert ev.findings.total == 1 and ev.findings.suppressed == 1
    assert ev.scope.components == len(data["components"])


@pytest.mark.parametrize(
    "data", [b"[]", b'{"matchSummary": {}}', b'{"components": [], "matchSummary": []}']
)
def test_invalid_sonatype(data) -> None:
    assert not sonatype.parse(data).parseable
