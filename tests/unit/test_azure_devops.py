"""Azure DevOps connector against real responses from public projects
(tests/fixtures/azure-real/)."""

from __future__ import annotations

import base64
import io
import json
import re
import zipfile

import pytest

from scanproof.connectors.azure_devops import AzureDevOpsConnector
from scanproof.connectors.base import AuthError, ConnectorError
from scanproof.models import JobStatus
from scanproof.policy.engine import Decision
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.conftest import FIXTURES

BASE = "https://dev.azure.com"
A = FIXTURES / "azure-real"
REPORT = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()


def zipped(artifact: str, files: dict[str, bytes]) -> bytes:
    """Real layout (seen in run 40463111410): every entry under '<artifact name>/'."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{artifact}/", b"")
        for name, data in files.items():
            zf.writestr(f"{artifact}/{name}", data)
    return buf.getvalue()


def serve(router, org: str, build: str, zips: dict[str, bytes] | None = None) -> str:
    d = A / org / build
    api = f"{BASE}/{org}/public/_apis/build/builds/{build}"
    router.get(url__regex=rf"^{re.escape(api)}\?api-version=.*").respond(
        content=(d / "build.json").read_bytes()
    )
    router.get(url__regex=rf"^{re.escape(api)}/timeline\?.*").respond(
        content=(d / "timeline.json").read_bytes()
    )
    for f in d.glob("timeline-*.json"):
        tid = f.stem.removeprefix("timeline-")
        router.get(url__regex=rf"^{re.escape(api)}/timeline/{tid}\?.*").respond(
            content=f.read_bytes()
        )
    for name, data in (zips or {}).items():
        router.get(
            url__regex=rf"^{re.escape(api)}/artifacts\?artifactName={re.escape(name)}&%24format=zip.*"
        ).respond(content=data, headers={"Content-Type": "application/zip"})
    if (d / "artifacts.json").exists():
        router.get(url__regex=rf"^{re.escape(api)}/artifacts\?api-version=.*").respond(
            content=(d / "artifacts.json").read_bytes()
        )
    return api


def records(org: str, build: str) -> list[dict]:
    return json.loads((A / org / build / "timeline.json").read_text())["records"]


@pytest.fixture
def azure(sleeps):
    with AzureDevOpsConnector(BASE, "pat-secret", sleep=sleeps.append) as c:
        yield c


def policy(job: str, artifact: str, report: str = "semgrep.json", **checks) -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "azure-devops", "id": "x/public"},
            "requirements": [
                {
                    "id": "SAST",
                    "tool": "semgrep",
                    "job_name": job,
                    "artifact_name": artifact,
                    "report_path": report,
                    "checks": {"same_commit": True, **checks},
                }
            ],
        }
    )


def verify(azure, org, build, pol):
    return verify_pipeline(
        azure, pol, instance_url=BASE, project=f"{org}/public", pipeline_id=int(build)
    )


def codes(report) -> dict[str, str]:
    return {
        c.check: c.code for r in report.requirements for c in r.checks if c.outcome.value != "PASS"
    }


# ---------------------------------------------------------------- jobs


def test_continue_on_error_job_is_a_masked_failure(azure, mock_api) -> None:
    """dnceng-public 1650345: tasks failed under continueOnError; build partiallySucceeded."""
    serve(mock_api, "dnceng-public", "1650345")
    jobs = {j.name: j for j in azure.list_jobs("dnceng-public/public", 1650345)}
    job = jobs["Tests: Ubuntu x64"]
    assert job.status is JobStatus.FAILED and job.allow_failure
    assert "Run Quarantined Tests" in job.raw_status
    assert azure.get_pipeline("dnceng-public/public", 1650345).status == "partiallySucceeded"


def test_masked_job_blocks_even_with_a_good_report(azure, mock_api) -> None:
    zips = {
        "Linux_Quarantined_Test_Logs": zipped(
            "Linux_Quarantined_Test_Logs", {"semgrep.json": REPORT}
        )
    }
    serve(mock_api, "dnceng-public", "1650345", zips)
    report = verify(
        azure,
        "dnceng-public",
        "1650345",
        policy("Tests: Ubuntu x64", "Linux_Quarantined_Test_Logs"),
    )
    assert report.decision is Decision.BLOCKED
    assert codes(report) == {"job_success": "FAILURE_MASKED_BY_ALLOW_FAILURE"}


def test_stage_qualified_names_and_verified_report(azure, mock_api) -> None:
    """azure-sdk 7003618: job 'Job' in stage 'SDK Generation', artifact published by that job."""
    zips = {"packages": zipped("packages", {"semgrep.json": REPORT})}
    serve(mock_api, "azure-sdk", "7003618", zips)
    names = [j.name for j in azure.list_jobs("azure-sdk/public", 7003618)]
    assert names == ["SDK Generation / Job"]
    report = verify(azure, "azure-sdk", "7003618", policy("Job", "packages"))
    assert report.decision is Decision.VERIFIED, codes(report)


def test_artifact_published_by_another_job_is_not_evidence(azure, mock_api) -> None:
    """dnceng-public 1650345: 'Windows_Quarantined_Test_Logs' was published by the Windows job."""
    zips = {
        "Windows_Quarantined_Test_Logs": zipped(
            "Windows_Quarantined_Test_Logs", {"semgrep.json": REPORT}
        )
    }
    serve(mock_api, "dnceng-public", "1650345", zips)
    report = verify(
        azure,
        "dnceng-public",
        "1650345",
        policy("Tests: Ubuntu x64", "Windows_Quarantined_Test_Logs", job_success=False),
    )
    assert codes(report) == {"report": "REPORT_MISSING"}
    assert "published by another job" in report.requirements[0].checks[-1].message


def test_rerun_job_reads_the_earlier_attempt(azure, mock_api) -> None:
    """azure-sdk 6975296: 'Pack Crates' attempt 2; attempt 1 lives in another timeline."""
    serve(mock_api, "azure-sdk", "6975296")
    attempts = [
        j for j in azure.list_jobs("azure-sdk/public", 6975296) if j.name.endswith("Pack Crates")
    ]
    assert sorted(j.attempt for j in attempts) == [1, 2]


def test_artifact_from_the_failed_first_attempt_is_not_the_latest_attempts(azure, mock_api) -> None:
    zips = {"packages-FailedAttempt1": zipped("packages-FailedAttempt1", {"semgrep.json": REPORT})}
    serve(mock_api, "azure-sdk", "6975296", zips)
    report = verify(
        azure,
        "azure-sdk",
        "6975296",
        policy("Pack Crates", "packages-FailedAttempt1", job_success=False),
    )
    assert codes(report) == {"report": "REPORT_MISSING"}


def test_report_at_the_zip_root_is_also_found(azure, mock_api) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("semgrep.json", REPORT)
    serve(mock_api, "azure-sdk", "7003618", {"packages": buf.getvalue()})
    assert (
        verify(azure, "azure-sdk", "7003618", policy("Job", "packages")).decision
        is Decision.VERIFIED
    )


@pytest.mark.parametrize(
    ("result", "state", "status", "masked"),
    [
        ("succeeded", "completed", JobStatus.SUCCESS, False),
        ("succeededWithIssues", "completed", JobStatus.FAILED, True),
        ("failed", "completed", JobStatus.FAILED, False),
        ("canceled", "completed", JobStatus.CANCELED, False),
        ("abandoned", "completed", JobStatus.CANCELED, False),
        ("skipped", "completed", JobStatus.SKIPPED, False),
        ("somethingNew", "completed", JobStatus.UNKNOWN, False),
        (None, "inProgress", JobStatus.RUNNING, False),
        (None, "pending", JobStatus.PENDING, False),
    ],
)
def test_result_mapping(azure, result, state, status, masked) -> None:
    rec = {
        "id": "98e09d1a-2dd9-54c0-d318-0eac30bf38a6",
        "type": "Job",
        "name": "j",
        "result": result,
        "state": state,
    }
    job = azure._to_job(rec, {rec["id"]: rec}, "a" * 40, 1)
    assert (job.status, job.allow_failure) == (status, masked)


# ---------------------------------------------------------------- auth and errors


def test_pat_goes_as_basic_only_to_the_api_origin(azure, mock_api) -> None:
    serve(
        mock_api, "azure-sdk", "7003618", {"packages": zipped("packages", {"semgrep.json": REPORT})}
    )
    verify(azure, "azure-sdk", "7003618", policy("Job", "packages"))
    expected = "Basic " + base64.b64encode(b":pat-secret").decode()
    assert {c.request.headers.get("authorization") for c in mock_api.calls} == {expected}


def test_bearer_for_system_access_token(mock_api) -> None:
    serve(mock_api, "azure-sdk", "7003618")
    with AzureDevOpsConnector(BASE, "oauth", auth_scheme="bearer") as c:
        c.get_pipeline("azure-sdk/public", 7003618)
    assert mock_api.calls[-1].request.headers["authorization"] == "Bearer oauth"


def test_sign_in_page_is_an_auth_error(azure, mock_api) -> None:
    mock_api.get(url__regex=r".*/_apis/build/builds/1\?.*").respond(
        203, text="<html>sign in</html>"
    )
    with pytest.raises(AuthError, match="sign-in page"):
        azure.get_pipeline("org/proj", 1)


def test_pipeline_artifact_redirect_does_not_carry_the_token(azure, mock_api) -> None:
    """Real (azure-sdk): Pipeline Artifacts 302 to artifacts.visualstudio.com, unsigned."""
    api = serve(mock_api, "azure-sdk", "7003618")
    target = (
        "https://artprodcus3.artifacts.visualstudio.com/x/_apis/artifact/abc/content?format=zip"
    )
    mock_api.get(
        url__regex=rf"^{re.escape(api)}/artifacts\?artifactName=packages&%24format=zip.*"
    ).respond(302, headers={"Location": target})
    mock_api.get(target).respond(401)
    report = verify(azure, "azure-sdk", "7003618", policy("Job", "packages"))
    assert report.decision is Decision.INDETERMINATE
    assert "PublishBuildArtifacts" in report.requirements[0].checks[-1].message
    leaked = [
        c
        for c in mock_api.calls
        if c.request.url.host != "dev.azure.com" and "authorization" in c.request.headers
    ]
    assert leaked == []


@pytest.mark.parametrize("bad", ["org", "org/proj/extra", "../proj", "org/.."])
def test_project_must_be_org_and_project(azure, bad) -> None:
    with pytest.raises(ConnectorError, match="organization"):
        azure.get_pipeline(bad, 1)


def test_artifact_name_is_required_by_the_policy() -> None:
    with pytest.raises(ValueError, match="set artifact_name"):
        Policy.model_validate(
            {
                "apiVersion": "scanproof.dev/v1alpha1",
                "kind": "PipelineAssurancePolicy",
                "project": {"provider": "azure-devops", "id": "o/p"},
                "requirements": [
                    {"id": "R", "tool": "semgrep", "job_name": "j", "report_path": "r"}
                ],
            }
        )
