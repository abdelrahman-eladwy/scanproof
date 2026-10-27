"""GitHub Actions connector, driven by REAL API responses from this repository's
`github-contract` workflow run (tests/fixtures/github-real/, no user/actor data)."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import httpx
import pytest

from scanproof.connectors.base import AuthError, ConnectorError, ErrorKind, NotFoundError
from scanproof.connectors.github import GitHubConnector
from scanproof.inspection import inspect_pipeline
from scanproof.models import JobStatus
from scanproof.policy.engine import Decision
from scanproof.policy.models import Policy, PolicyError, load_policy
from scanproof.verification import verify_pipeline
from tests.conftest import FIXTURES

API = "https://api.github.com"
REPO = "abdelrahman-eladwy/scanproof"
REAL = FIXTURES / "github-real"
RUN = json.loads((REAL / "run.json").read_text())
JOBS = json.loads((REAL / "jobs.json").read_text())
ARTIFACTS = json.loads((REAL / "artifacts.json").read_text())
RUN_ID = RUN["id"]
TOKEN = "ghp_TEST-token-do-not-leak"
SEMGREP_JSON = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()
SEMGREP_SARIF = (FIXTURES / "sarif/semgrep.sarif").read_bytes()


def job_id(name: str) -> int:
    return next(j["id"] for j in JOBS["jobs"] if j["name"] == name)


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def gh(sleeps):
    with GitHubConnector(API, TOKEN, sleep=sleeps.append, max_retries=1) as conn:
        yield conn


def serve(
    mock_api,
    *,
    annotations_status: int = 200,
    run_overrides=None,
    zip_bytes=None,
    digest: str | None = "match",
    page_size: int = 2,
):
    base = f"{API}/repos/{REPO}/actions"
    mock_api.get(f"{base}/runs/{RUN_ID}").respond(json={**RUN, **(run_overrides or {})})

    jobs = JOBS["jobs"]
    pages = [jobs[i : i + page_size] for i in range(0, len(jobs), page_size)]

    def jobs_page(request: httpx.Request) -> httpx.Response:
        n = int(request.url.params.get("page", "1"))
        headers = {}
        if n < len(pages):
            headers["Link"] = (
                f'<{base}/runs/{RUN_ID}/jobs?filter=all&per_page=100&page={n + 1}>; rel="next"'
            )
        return httpx.Response(
            200, json={"total_count": len(jobs), "jobs": pages[n - 1]}, headers=headers
        )

    mock_api.get(f"{base}/runs/{RUN_ID}/jobs").mock(side_effect=jobs_page)

    for j in jobs:
        path = REAL / f"annotations-{j['id']}.json"
        body = json.loads(path.read_text()) if path.exists() else []
        route = mock_api.get(f"{API}/repos/{REPO}/check-runs/{j['id']}/annotations")
        route.respond(annotations_status, json=body if annotations_status == 200 else {})

    archive = (
        zip_bytes
        if zip_bytes is not None
        else make_zip({"semgrep.json": SEMGREP_JSON, "semgrep.sarif": SEMGREP_SARIF})
    )
    artifacts = json.loads(json.dumps(ARTIFACTS))
    art = artifacts["artifacts"][0]
    if digest == "match":
        art["digest"] = "sha256:" + hashlib.sha256(archive).hexdigest()
    elif digest is None:
        art.pop("digest", None)
    mock_api.get(f"{base}/runs/{RUN_ID}/artifacts").respond(json=artifacts)
    storage = "https://pipelines.blob.example.net/artifact.zip?sig=x"
    mock_api.get(f"{base}/artifacts/{art['id']}/zip").respond(302, headers={"Location": storage})
    return mock_api.get(storage).respond(content=archive)


def inspect(gh, mock_api, **kw):
    serve(mock_api, **kw)
    return {
        j.name: j
        for j in inspect_pipeline(gh, instance_url=API, project=REPO, pipeline_id=RUN_ID).jobs
    }


# ---------------------------------------------------------------- jobs (real responses)


def test_real_jobs_are_mapped(gh, mock_api) -> None:
    jobs = inspect(gh, mock_api)
    assert set(jobs) == {"sast", "masked-step", "masked-job", "skipped-scan", "self-verify"}
    assert jobs["sast"].latest.status is JobStatus.SUCCESS
    assert jobs["sast"].latest.masking_checked is True
    assert jobs["skipped-scan"].latest.status is JobStatus.SKIPPED
    assert all(j.commit_matches_pipeline for j in jobs.values())


def test_step_continue_on_error_is_detected_from_annotations(gh, mock_api) -> None:
    """GitHub reports this job (and the failing step) as success; only the annotation tells."""
    job = inspect(gh, mock_api)["masked-step"].latest
    assert job.status is JobStatus.FAILED and job.allow_failure
    assert "exit code 1" in job.raw_status


def test_job_continue_on_error_in_successful_run(gh, mock_api) -> None:
    job = inspect(gh, mock_api)["masked-job"].latest
    assert job.status is JobStatus.FAILED and job.allow_failure


def test_failed_job_in_running_run_is_not_called_masked(gh, mock_api) -> None:
    job = inspect(gh, mock_api, run_overrides={"status": "in_progress", "conclusion": None})[
        "masked-job"
    ].latest
    assert job.status is JobStatus.FAILED and not job.allow_failure


def test_annotations_unreadable_means_masking_unknown(gh, mock_api) -> None:
    jobs = inspect(gh, mock_api, annotations_status=403)
    assert jobs["sast"].latest.masking_checked is False
    assert jobs["masked-step"].latest.status is JobStatus.SUCCESS  # can't tell -> not "failed"


# ---------------------------------------------------------------- artifacts


def _sast_job(gh):
    return next(j for j in gh.list_jobs(REPO, RUN_ID) if j.name == "sast")


def test_report_extracted_from_artifact_zip(gh, mock_api) -> None:
    storage = serve(mock_api)
    data = gh.fetch_report(REPO, _sast_job(gh), "semgrep.json", "semgrep-report")
    assert data == SEMGREP_JSON
    assert "Authorization" not in storage.calls.last.request.headers  # blob storage, cross-origin


def test_real_recorded_digest_rejects_a_different_zip(gh, mock_api) -> None:
    """Keeps GitHub's real recorded digest; our test zip differs, as a tampered one would."""
    serve(mock_api, digest="real")
    with pytest.raises(ConnectorError) as exc:
        gh.fetch_report(REPO, _sast_job(gh), "semgrep.json", "semgrep-report")
    assert exc.value.kind is ErrorKind.INTEGRITY
    assert ARTIFACTS["artifacts"][0]["digest"] in str(exc.value)


def test_artifact_without_digest_is_accepted(gh, mock_api) -> None:
    serve(mock_api, digest=None)
    assert gh.fetch_report(REPO, _sast_job(gh), "./semgrep.json", "semgrep-report") == SEMGREP_JSON


@pytest.mark.parametrize(
    ("artifact", "path", "message"),
    [
        ("nope", "semgrep.json", "No artifact named 'nope'"),
        ("semgrep-report", "other.json", "not found in artifact"),
    ],
)
def test_missing_report_is_not_found(gh, mock_api, artifact, path, message) -> None:
    serve(mock_api)
    with pytest.raises(NotFoundError, match=message):
        gh.fetch_report(REPO, _sast_job(gh), path, artifact)


def test_artifact_name_required(gh, mock_api) -> None:
    serve(mock_api)
    with pytest.raises(ConnectorError, match="set artifact_name"):
        gh.fetch_report(REPO, _sast_job(gh), "semgrep.json", None)


def test_zip_member_size_cap(mock_api, sleeps) -> None:
    big = make_zip({"semgrep.json": b"x" * 5000})
    with GitHubConnector(API, TOKEN, max_artifact_bytes=2000, sleep=sleeps.append) as small:
        serve(mock_api, zip_bytes=big)
        with pytest.raises(ConnectorError) as exc:
            small.fetch_report(REPO, _sast_job(small), "semgrep.json", "semgrep-report")
    assert exc.value.kind is ErrorKind.LIMIT_EXCEEDED


def test_corrupt_zip_is_integrity_failure(gh, mock_api) -> None:
    serve(mock_api, zip_bytes=b"PK\x03\x04 definitely not a zip")
    with pytest.raises(ConnectorError) as exc:
        gh.fetch_report(REPO, _sast_job(gh), "semgrep.json", "semgrep-report")
    assert exc.value.kind is ErrorKind.INTEGRITY


def test_path_traversal_rejected(gh, mock_api) -> None:
    serve(mock_api)
    with pytest.raises(ConnectorError, match=r"'\.\.'"):
        gh.fetch_report(REPO, _sast_job(gh), "../etc/passwd", "semgrep-report")


# ---------------------------------------------------------------- errors & safety


def test_repo_must_be_owner_slash_name(gh) -> None:
    with pytest.raises(ConnectorError, match="owner/name"):
        gh.get_pipeline("not a repo", 1)


@pytest.mark.parametrize(
    ("status", "headers", "exc_type", "kind"),
    [
        (401, {}, AuthError, ErrorKind.AUTH),
        (404, {}, NotFoundError, ErrorKind.NOT_FOUND),
        (403, {"x-ratelimit-remaining": "0"}, ConnectorError, ErrorKind.RATE_LIMITED),
    ],
)
def test_error_mapping(gh, mock_api, status, headers, exc_type, kind) -> None:
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}").respond(status, headers=headers)
    with pytest.raises(exc_type) as exc:
        gh.get_pipeline(REPO, RUN_ID)
    assert exc.value.kind is kind
    assert TOKEN not in str(exc.value)


def test_secondary_rate_limit_is_retried(gh, mock_api, sleeps) -> None:
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}").side_effect = [
        httpx.Response(403, headers={"retry-after": "3"}),
        httpx.Response(200, json=RUN),
    ]
    assert gh.get_pipeline(REPO, RUN_ID).id == RUN_ID
    assert sleeps == [3.0]


def test_pagination_link_cannot_leave_api_origin(gh, mock_api) -> None:
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}").respond(json=RUN)
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}/jobs").respond(
        json={"jobs": []}, headers={"Link": '<https://evil.example/next>; rel="next"'}
    )
    with pytest.raises(ConnectorError) as exc:
        gh.list_jobs(REPO, RUN_ID)
    assert exc.value.kind is ErrorKind.UNSAFE_REDIRECT


def test_github_headers_and_bearer(gh, mock_api) -> None:
    route = mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}").respond(json=RUN)
    gh.get_pipeline(REPO, RUN_ID)
    headers = route.calls.last.request.headers
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert TOKEN not in repr(gh)


# ---------------------------------------------------------------- end to end: verify


POLICIES = FIXTURES.parent.parent / "examples/policies"


@pytest.mark.parametrize(
    ("policy", "decision", "code"),
    [
        ("github-self-sast.yaml", Decision.VERIFIED, None),
        ("github-self-masked-step.yaml", Decision.BLOCKED, "FAILURE_MASKED_BY_ALLOW_FAILURE"),
        ("github-self-masked-job.yaml", Decision.BLOCKED, "FAILURE_MASKED_BY_ALLOW_FAILURE"),
        ("github-self-skipped.yaml", Decision.BLOCKED, "JOB_NOT_SUCCESS"),
    ],
)
def test_verify_real_run(gh, mock_api, policy, decision, code) -> None:
    serve(mock_api)
    report = verify_pipeline(
        gh, load_policy(POLICIES / policy), instance_url=API, project=REPO, pipeline_id=RUN_ID
    )
    assert report.decision is decision
    if code:
        assert code in {c.code for r in report.requirements for c in r.checks}


def test_verify_without_checks_permission_is_indeterminate(gh, mock_api) -> None:
    serve(mock_api, annotations_status=403)
    report = verify_pipeline(
        gh,
        load_policy(POLICIES / "github-self-sast.yaml"),
        instance_url=API,
        project=REPO,
        pipeline_id=RUN_ID,
    )
    assert report.decision is Decision.INDETERMINATE
    assert "STEP_MASKING_UNKNOWN" in {c.code for r in report.requirements for c in r.checks}


def test_tampered_artifact_blocks(gh, mock_api) -> None:
    serve(mock_api, digest="real")
    report = verify_pipeline(
        gh,
        load_policy(POLICIES / "github-self-sast.yaml"),
        instance_url=API,
        project=REPO,
        pipeline_id=RUN_ID,
    )
    assert report.decision is Decision.BLOCKED
    assert any("digest mismatch" in c.message for r in report.requirements for c in r.checks)


def test_github_policy_requires_artifact_name() -> None:
    with pytest.raises(ValueError, match="set artifact_name"):
        Policy.model_validate(
            {
                "apiVersion": "scanproof.dev/v1alpha1",
                "kind": "PipelineAssurancePolicy",
                "project": {"provider": "github", "id": REPO},
                "requirements": [
                    {"id": "R", "tool": "semgrep", "job_name": "sast", "report_path": "x"}
                ],
            }
        )
    assert PolicyError  # imported for parity with other policy tests


# ---------------------------------------------------------------- remaining paths


def test_status_mapping_for_unfinished_and_unknown_jobs(gh, mock_api) -> None:
    jobs = json.loads(json.dumps(JOBS))
    jobs["jobs"][0].update(status="in_progress", conclusion=None)
    jobs["jobs"][1].update(status="completed", conclusion="neutral")
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}").respond(json=RUN)
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}/jobs").respond(json=jobs)
    mock_api.get(url__regex=r".*/annotations").respond(json=[])
    got = {j.name: j.status for j in gh.list_jobs(REPO, RUN_ID)}
    assert got[jobs["jobs"][0]["name"]] is JobStatus.RUNNING
    assert got[jobs["jobs"][1]["name"]] is JobStatus.UNKNOWN  # never treated as success


def test_expired_artifact_is_missing(gh, mock_api) -> None:
    serve(mock_api)
    expired = json.loads(json.dumps(ARTIFACTS))
    expired["artifacts"][0]["expired"] = True
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}/artifacts").respond(json=expired)
    with pytest.raises(NotFoundError, match="expired"):
        gh.fetch_report(REPO, _sast_job(gh), "semgrep.json", "semgrep-report")


@pytest.mark.parametrize(
    ("status", "kind"),
    [(410, ErrorKind.NOT_FOUND), (502, ErrorKind.SERVER), (418, ErrorKind.INVALID_RESPONSE)],
)
def test_more_status_codes(gh, mock_api, status, kind) -> None:
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}").respond(status)
    with pytest.raises(ConnectorError) as exc:
        gh.get_pipeline(REPO, RUN_ID)
    assert exc.value.kind is kind


def test_invalid_payloads(gh, mock_api) -> None:
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}").respond(json={"id": 1})
    with pytest.raises(ConnectorError) as exc:
        gh.get_pipeline(REPO, RUN_ID)
    assert exc.value.kind is ErrorKind.INVALID_RESPONSE
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}").respond(json=RUN)
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}/jobs").respond(json={"jobs": {}})
    with pytest.raises(ConnectorError, match="Expected a list"):
        gh.list_jobs(REPO, RUN_ID)


def test_anonymous_github_hint(mock_api) -> None:
    mock_api.get(f"{API}/repos/{REPO}/actions/runs/{RUN_ID}").respond(401)
    with GitHubConnector(API, None, anonymous=True) as anon, pytest.raises(AuthError) as exc:
        anon.get_pipeline(REPO, RUN_ID)
    assert "Anonymous access" in str(exc.value)


def test_basic_auth_username_cannot_smuggle_a_colon_or_control_chars() -> None:
    from scanproof.connectors.base import AuthError
    from scanproof.connectors.jenkins import JenkinsConnector

    for bad in ("a:b", "a\nb", "a\x00b"):
        with pytest.raises(AuthError, match="Username"):
            JenkinsConnector("https://jenkins.example.com", "t", username=bad)
