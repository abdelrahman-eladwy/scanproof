"""Provider error matrix: a failed report fetch must never be treated as a clean scan."""

from __future__ import annotations

import pytest

from scanproof.policy.engine import Decision
from scanproof.verification import verify_pipeline
from tests.conftest import BASE, FIXTURES
from tests.fake_gitlab import FakeGitLab
from tests.unit.test_verify_scenarios import make_policy

SEMGREP_OK = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()
TRIVY_OK = (FIXTURES / "trivy/trivy-python.json").read_bytes()


@pytest.mark.parametrize("status", [401, 403, 429, 500, 502, 503, 504])
def test_report_http_failure_cannot_be_verified(connector, mock_api, status):
    gl = FakeGitLab(mock_api)
    gl.job(8821, "semgrep-sast", files={"semgrep.json": status})
    gl.job(8830, "trivy-image", files={"trivy.json": TRIVY_OK})
    gl.install()
    report = verify_pipeline(
        connector,
        make_policy(),
        instance_url=BASE,
        project="123",
        pipeline_id=1042,
    )
    assert report.decision is not Decision.VERIFIED
    assert report.exit_code != 0


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"null",
        b"[]",
        b"{}",
        b'{"results":null}',
        b'{"results":[], "errors": "not-an-array"}',
        b'{"results":[], "errors":[], "paths":{"scanned":[]}}',
        b'{"results":[], "errors":[], "paths":{"scanned":["\\\\ud800"]}}',
    ],
)
def test_corrupt_or_incomplete_semgrep_cannot_be_verified(connector, mock_api, payload):
    gl = FakeGitLab(mock_api)
    gl.job(8821, "semgrep-sast", files={"semgrep.json": payload})
    gl.job(8830, "trivy-image", files={"trivy.json": TRIVY_OK})
    gl.install()
    report = verify_pipeline(
        connector,
        make_policy(),
        instance_url=BASE,
        project="123",
        pipeline_id=1042,
    )
    assert report.decision is not Decision.VERIFIED
    assert report.exit_code != 0
    report.model_dump_json()
