"""Bitbucket Pipelines connector and Code Insights adapter against real responses from public
Atlassian repositories (tests/fixtures/bitbucket-real/)."""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import quote

import pytest

from scanproof.connectors.bitbucket import INSIGHTS_FORMAT, BitbucketConnector
from scanproof.models import JobStatus
from scanproof.policy.engine import Decision
from scanproof.policy.models import Policy
from scanproof.scanners import get_adapter
from scanproof.verification import verify_pipeline
from tests.conftest import FIXTURES

API = "https://api.bitbucket.org/2.0"
B = FIXTURES / "bitbucket-real"
REPO = "atlassian/aws-s3-deploy"
GIT_SECRETS = "Git secrets Security Scan report"


def load(repo: str, n: int, name: str):
    return json.loads((B / repo.replace("/", "__") / str(n) / name).read_text())


def serve(router, repo: str, n: int, *, steps: list | None = None) -> dict:
    p = load(repo, n, "pipeline.json")
    base = f"{API}/repositories/{repo}"
    router.get(f"{base}/pipelines/{n}").respond(json=p)
    router.get(
        url__regex=rf"^{re.escape(base)}/pipelines/{re.escape(quote(p['uuid']))}/steps/.*"
    ).respond(
        json={"values": steps if steps is not None else load(repo, n, "steps.json")["values"]}
    )
    sha = p["target"]["commit"]["hash"]
    router.get(url__regex=rf"^{re.escape(base)}/commit/{sha}/reports\?.*").respond(
        json=load(repo, n, "reports.json")
    )
    d = B / repo.replace("/", "__") / str(n)
    for f in d.glob("report-*-annotations.json"):
        rid = "{" + f.name.removeprefix("report-").removesuffix("-annotations.json") + "}"
        router.get(
            url__regex=rf"^{re.escape(base)}/commit/{sha}/reports/{re.escape(quote(rid))}/annotations.*"
        ).respond(content=f.read_bytes())
    return p


@pytest.fixture
def bb(sleeps):
    with BitbucketConnector(API, "access-token", sleep=sleeps.append) as c:
        yield c


def policy(job: str, report: str = GIT_SECRETS) -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "bitbucket", "id": REPO},
            "requirements": [
                {
                    "id": "SECRETS",
                    "tool": "bitbucket-code-insights",
                    "job_name": job,
                    "report_path": report,
                }
            ],
        }
    )


def verify(bb, n, pol):
    return verify_pipeline(bb, pol, instance_url=API, project=REPO, pipeline_id=n)


def codes(report) -> dict[str, str]:
    return {
        c.check: c.code for r in report.requirements for c in r.checks if c.outcome.value != "PASS"
    }


def test_security_scan_step_and_code_insights_report(bb, mock_api) -> None:
    serve(mock_api, REPO, 187)
    report = verify(bb, 187, policy("Security Scan"))
    assert report.decision is Decision.VERIFIED, codes(report)
    ev = report.evidence["SECRETS"]
    assert (
        ev.tool == "bitbucket-code-insights"
        and ev.scanner_name == "Created by git-secrets-scan pipe."
    )
    assert ev.findings.total == 0


def test_failed_step_in_a_failed_pipeline(bb, mock_api) -> None:
    serve(mock_api, REPO, 179)
    report = verify(bb, 179, policy("Test"))
    assert codes(report)["job_success"] == "JOB_NOT_SUCCESS"


def test_newest_of_two_reports_with_the_same_title_wins(bb, mock_api) -> None:
    """Pipeline 179's commit carries two git-secrets reports (a re-run)."""
    serve(mock_api, REPO, 179)
    reports = [r for r in load(REPO, 179, "reports.json")["values"] if r["title"] == GIT_SECRETS]
    newest = max(reports, key=lambda r: r["created_on"])["uuid"]
    verify(bb, 179, policy("Security Scan"))
    fetched = [
        c.request.url.path for c in mock_api.calls if c.request.url.path.endswith("/annotations")
    ]
    assert fetched and all(quote(newest) in p or newest in p for p in fetched)


def test_ignored_step_failure_is_a_masked_failure(bb, mock_api) -> None:
    """on-fail: strategy: ignore: a FAILED step in a pipeline that still succeeded."""
    steps = load(REPO, 187, "steps.json")["values"]
    for s in steps:
        if s["name"] == "Security Scan":
            s["state"]["result"] = {
                "name": "FAILED",
                "type": "pipeline_step_state_completed_failed",
            }
    serve(mock_api, REPO, 187, steps=steps)
    report = verify(bb, 187, policy("Security Scan"))
    assert report.decision is Decision.BLOCKED
    assert codes(report) == {"job_success": "FAILURE_MASKED_BY_ALLOW_FAILURE"}


def test_paused_pipeline_manual_step(bb, mock_api) -> None:
    serve(mock_api, REPO, 182)
    jobs = {j.name: j for j in bb.list_jobs(REPO, 182)}
    assert jobs["Release development version"].status is JobStatus.MANUAL
    assert bb.get_pipeline(REPO, 182).status == "in_progress"


def test_report_that_does_not_exist(bb, mock_api) -> None:
    serve(mock_api, REPO, 187)
    report = verify(bb, 187, policy("Security Scan", report="Snyk report"))
    assert codes(report) == {"report": "REPORT_MISSING"}


def test_pagination_cannot_leave_the_api_origin(bb, mock_api) -> None:
    sha = load(REPO, 187, "pipeline.json")["target"]["commit"]["hash"]
    # registered before serve(), so it wins over the real reports page
    mock_api.get(url__regex=rf".*/commit/{sha}/reports\?pagelen=100$").respond(
        json={"values": [], "next": "https://evil.example/2.0/page2"}
    )
    serve(mock_api, REPO, 187)
    report = verify(bb, 187, policy("Security Scan"))
    assert report.decision is Decision.INDETERMINATE
    assert codes(report) == {"report": "EVIDENCE_UNAVAILABLE"}
    assert not any(c.request.url.host == "evil.example" for c in mock_api.calls)


def test_bearer_by_default_basic_with_a_user(mock_api) -> None:
    serve(mock_api, REPO, 187)
    with BitbucketConnector(API, "tok") as c:
        c.get_pipeline(REPO, 187)
    assert mock_api.calls[-1].request.headers["authorization"] == "Bearer tok"
    with BitbucketConnector(API, "api-token", username="me@example.com") as c:
        c._pipelines.clear()
        c.get_pipeline(REPO, 187)
    expected = "Basic " + base64.b64encode(b"me@example.com:api-token").decode()
    assert mock_api.calls[-1].request.headers["authorization"] == expected


# ---------------------------------------------------------------- adapter


def doc(**over) -> bytes:
    base = {
        "format": INSIGHTS_FORMAT,
        "report": {"title": "t", "report_type": "SECURITY"},
        "annotations": [],
        "annotations_complete": True,
    }
    return json.dumps(base | over).encode()


def test_adapter_counts_annotations_by_severity() -> None:
    notes = [{"severity": "HIGH"}, {"severity": "high"}, {"severity": None}]
    ev = get_adapter("bitbucket-code-insights").parse(doc(annotations=notes))
    assert ev.parseable and ev.findings.by_severity == {"HIGH": 2, "UNKNOWN": 1}


def test_adapter_incomplete_annotations_are_unknown_not_zero() -> None:
    ev = get_adapter("bitbucket-code-insights").parse(doc(annotations_complete=False))
    assert ev.parseable and ev.findings is None


@pytest.mark.parametrize(
    "raw",
    [doc(report={"result": "PENDING"}), b'{"format": "other"}', b"[]", doc(annotations="x")],
)
def test_adapter_rejects_pending_and_foreign_documents(raw) -> None:
    assert get_adapter("bitbucket-code-insights").parse(raw).parseable is False
