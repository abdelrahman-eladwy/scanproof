"""A job the API returned without its run/build id is UNKNOWN, never a missing report.

GitHub's job listing carries `run_id`; if a response lacked it, `fetch_report` asked for
`/actions/runs/None/artifacts`, got a 404, and the NotFoundError became REPORT_MISSING: a
policy FAIL (exit 1) based on data ScanProof never had. Jenkins and Azure DevOps substituted
build 0 the same way. Missing data must stay UNKNOWN (rule 1).
"""

from __future__ import annotations

import pytest
import respx

from scanproof.connectors.azure_devops import AzureDevOpsConnector
from scanproof.connectors.base import ConnectorError, ErrorKind, NotFoundError
from scanproof.connectors.github import GitHubConnector
from scanproof.connectors.jenkins import JenkinsConnector
from scanproof.models import Job, JobStatus

JOB = Job(id=1, name="sast", status=JobStatus.SUCCESS, pipeline_id=None)


def _assert_unknown(exc: pytest.ExceptionInfo[ConnectorError]) -> None:
    assert not isinstance(exc.value, NotFoundError)  # would become REPORT_MISSING / FAIL
    assert exc.value.kind is ErrorKind.INVALID_RESPONSE
    assert "sast" in exc.value.message


@respx.mock(assert_all_mocked=True, assert_all_called=False)
def test_github_job_without_run_id(respx_mock) -> None:
    respx_mock.route().respond(404)
    with (
        GitHubConnector("https://api.github.com", "ghp_test", sleep=lambda _: None) as gh,
        pytest.raises(ConnectorError) as exc,
    ):
        gh.fetch_report("acme/app", JOB, "semgrep.json", "semgrep")
    _assert_unknown(exc)
    assert not respx_mock.calls  # no request for /runs/None


@respx.mock(assert_all_mocked=True, assert_all_called=False)
def test_jenkins_job_without_build_number(respx_mock) -> None:
    respx_mock.route().respond(404)
    with (
        JenkinsConnector(
            "https://jenkins.example.com", "api-token", username="u", sleep=lambda _: None
        ) as jk,
        pytest.raises(ConnectorError) as exc,
    ):
        jk.fetch_report("app", JOB, "semgrep.json")
    _assert_unknown(exc)
    assert not respx_mock.calls  # no request for build 0


@respx.mock(assert_all_mocked=True, assert_all_called=False)
def test_azure_job_without_build_id(respx_mock) -> None:
    respx_mock.route().respond(404)
    with (
        AzureDevOpsConnector("https://dev.azure.com", "pat", sleep=lambda _: None) as az,
        pytest.raises(ConnectorError) as exc,
    ):
        az.fetch_report("org/project", JOB, "semgrep.json", "scans")
    _assert_unknown(exc)
    assert not respx_mock.calls  # no request for build 0
