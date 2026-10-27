"""Adapter tests. Fixtures under tests/fixtures/{semgrep,trivy} are REAL reports produced by
scanproof-e2e fixtures (Semgrep 1.181.1, Trivy 0.76.1); trivy-python.json is trimmed."""

from __future__ import annotations

import hashlib
import json

import pytest

from scanproof.evidence.models import ScanType
from scanproof.scanners import ADAPTERS, get_adapter
from scanproof.scanners.semgrep import SemgrepAdapter
from scanproof.scanners.trivy import TrivyAdapter
from tests.conftest import FIXTURES

semgrep = SemgrepAdapter()
trivy = TrivyAdapter()


def raw(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


# ---------------------------------------------------------------- shared failure modes


@pytest.mark.parametrize("adapter", [semgrep, trivy], ids=["semgrep", "trivy"])
class TestBadInput:
    def test_no_report(self, adapter) -> None:
        ev = adapter.parse(None)
        assert (ev.present, ev.parseable) == (False, False)
        assert ev.report_sha256 is None

    @pytest.mark.parametrize("data", [b"", b"   \n"])
    def test_empty_report(self, adapter, data) -> None:
        ev = adapter.parse(data)
        assert (ev.present, ev.parseable) == (True, False)
        assert ev.parse_error == "Report is empty"

    def test_truncated_json(self, adapter) -> None:
        ev = adapter.parse(b'{"results": [ truncated')
        assert not ev.parseable
        assert "not valid JSON" in ev.parse_error

    def test_not_json(self, adapter) -> None:
        assert not adapter.parse(b"<html>502 Bad Gateway</html>").parseable

    def test_binary_garbage(self, adapter) -> None:
        assert not adapter.parse(b"\xff\xfe\x00\x81").parseable

    def test_json_array(self, adapter) -> None:
        assert not adapter.parse(b"[]").parseable

    def test_unknown_fields_never_default_to_zero(self, adapter) -> None:
        ev = adapter.parse(b"{}")
        assert ev.findings is None
        assert ev.scope is None

    def test_sha256_is_over_exact_bytes(self, adapter) -> None:
        data = b'{"anything": 1}'
        assert adapter.parse(data).report_sha256 == hashlib.sha256(data).hexdigest()


def test_foreign_reports_are_rejected() -> None:
    assert not semgrep.parse(raw("trivy/trivy-alpine.json")).parseable
    assert not trivy.parse(raw("semgrep/semgrep-clean.json")).parseable


# ---------------------------------------------------------------- semgrep


def test_semgrep_findings_report() -> None:
    ev = semgrep.parse(raw("semgrep/semgrep-findings.json"))
    assert ev.parseable and ev.present
    assert ev.tool == "semgrep" and ev.scan_type is ScanType.SAST
    assert ev.tool_version == "1.181.1"
    assert ev.scanner_error_count == 0
    assert ev.scope.files_scanned == 1
    assert ev.scope.scanned_paths == ["examples/gitlab-ci/sample-app/app.py"]
    assert ev.findings.total == 6
    assert ev.findings.by_severity == {"ERROR": 4, "WARNING": 2}


def test_semgrep_clean_report_is_zero_not_unknown() -> None:
    ev = semgrep.parse(raw("semgrep/semgrep-clean.json"))
    assert ev.findings.total == 0
    assert ev.scanner_errors == []
    assert ev.scope.files_scanned == 1


def test_semgrep_report_with_parse_errors() -> None:
    ev = semgrep.parse(raw("semgrep/semgrep-errors.json"))
    assert ev.parseable  # the report itself is fine; the scan had problems
    assert ev.scanner_error_count == 1
    (err,) = ev.scanner_errors
    assert err.type == "Syntax error"
    assert err.level == "warn"
    assert err.path.endswith("bad.py")
    assert ev.scope.files_scanned == 2


def test_semgrep_without_paths_has_unknown_scope() -> None:
    data = json.loads(raw("semgrep/semgrep-clean.json"))
    del data["paths"]
    ev = semgrep.parse(json.dumps(data).encode())
    assert ev.parseable
    assert ev.scope is None  # unknown, not "0 files"


def test_semgrep_empty_scanned_list_is_zero_files() -> None:
    data = json.loads(raw("semgrep/semgrep-clean.json"))
    data["paths"]["scanned"] = []
    assert semgrep.parse(json.dumps(data).encode()).scope.files_scanned == 0


def test_semgrep_results_must_be_lists() -> None:
    assert not semgrep.parse(b'{"results": {}, "errors": []}').parseable


# ---------------------------------------------------------------- trivy


def test_trivy_image_report_binds_to_digest() -> None:
    ev = trivy.parse(raw("trivy/trivy-python.json"))
    assert ev.parseable
    assert ev.tool_version == "0.76.1"
    assert ev.scan_type is ScanType.CONTAINER
    assert ev.target.artifact_name == "python:3.12-slim"
    assert ev.target.artifact_type == "container_image"
    assert ev.target.image_id.startswith("sha256:")
    assert ev.target.digests() == {
        "sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"
    }
    assert len(ev.scope.scanned_paths) == 2
    assert ev.results_reported is True


def test_trivy_counts_severities() -> None:
    ev = trivy.parse(raw("trivy/trivy-alpine.json"))
    assert ev.findings.total == 2
    assert ev.findings.by_severity == {"UNKNOWN": 2}


def test_trivy_errors_are_unknown_not_zero() -> None:
    """Trivy's JSON has no error section; claiming 0 errors would be a false PASS."""
    assert trivy.parse(raw("trivy/trivy-alpine.json")).scanner_errors is None


def test_trivy_missing_vs_empty_results() -> None:
    data = json.loads(raw("trivy/trivy-alpine.json"))
    data["Results"] = []
    empty = trivy.parse(json.dumps(data).encode())
    assert empty.results_reported is True
    assert empty.findings.total == 0

    del data["Results"]
    missing = trivy.parse(json.dumps(data).encode())
    assert missing.parseable
    assert missing.results_reported is False
    assert missing.findings is None


def test_trivy_rejects_unsupported_schema() -> None:
    data = json.loads(raw("trivy/trivy-alpine.json"))
    data["SchemaVersion"] = 3
    ev = trivy.parse(json.dumps(data).encode())
    assert not ev.parseable
    assert "SchemaVersion" in ev.parse_error


def test_trivy_target_without_digest() -> None:
    data = json.loads(raw("trivy/trivy-alpine.json"))
    data["Metadata"].pop("RepoDigests")
    ev = trivy.parse(json.dumps(data).encode())
    assert ev.target.repo_digests is None
    assert ev.target.digests() == set()


# ---------------------------------------------------------------- registry


def test_registry() -> None:
    assert {
        "semgrep",
        "trivy",
        "gitlab-sast",
        "gitlab-container-scanning",
        "sarif",
        "cyclonedx",
    } <= set(ADAPTERS)
    assert get_adapter("Semgrep").tool == "semgrep"
    with pytest.raises(
        KeyError,
        match=r"Unsupported tool .nosuchscanner.\. Supported: bitbucket-code-insights, checkov, ",
    ):
        get_adapter("nosuchscanner")
