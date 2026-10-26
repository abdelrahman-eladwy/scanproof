"""Contract tests on REAL gitlab.com API responses (public projects, collected anonymously by
.github/workflows/gitlab-contract.yml and sanitized: no user, author or runner data)."""

from __future__ import annotations

import json

import httpx
import pytest

from scanproof.inspection import inspect_pipeline
from scanproof.models import JobStatus
from scanproof.policy.engine import Decision, Outcome
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.conftest import API, BASE, FIXTURES

REAL = FIXTURES / "gitlab-real"


def serve(mock_api, name: str, *, page_size: int = 20) -> tuple[dict, list]:
    """Serve a real pipeline + jobs, split into pages to exercise pagination."""
    pipeline = json.loads((REAL / name / "pipeline.json").read_text())
    jobs = json.loads((REAL / name / "jobs.json").read_text())
    base = f"{API}/projects/{pipeline['project_id']}"
    mock_api.get(f"{base}/pipelines/{pipeline['id']}").respond(json=pipeline)
    pages = [jobs[i : i + page_size] for i in range(0, len(jobs), page_size)] or [[]]

    def page(request: httpx.Request) -> httpx.Response:
        n = int(request.url.params.get("page", "1"))
        nxt = str(n + 1) if n < len(pages) else ""
        return httpx.Response(200, json=pages[n - 1], headers={"x-next-page": nxt})

    mock_api.get(f"{base}/pipelines/{pipeline['id']}/jobs").mock(side_effect=page)
    return pipeline, jobs


def inspect(connector, mock_api, name):
    pipeline, jobs = serve(mock_api, name)
    report = inspect_pipeline(
        connector,
        instance_url=BASE,
        project=str(pipeline["project_id"]),
        pipeline_id=pipeline["id"],
    )
    return pipeline, jobs, report


@pytest.mark.parametrize("name", ["semgrep", "cli"])
def test_every_real_job_is_parsed(connector, mock_api, name) -> None:
    pipeline, jobs, report = inspect(connector, mock_api, name)
    assert sum(j.attempts for j in report.jobs) == len(jobs)
    assert {j.name for j in report.jobs} == {j["name"] for j in jobs}
    assert all(j.latest.status is not JobStatus.UNKNOWN for j in report.jobs)
    assert all(j.commit_matches_pipeline is True for j in report.jobs)
    assert report.pipeline.sha == pipeline["sha"]


def test_real_retried_job(connector, mock_api) -> None:
    _, _, report = inspect(connector, mock_api, "cli")
    job = next(j for j in report.jobs if j.name == "snapcraft_release_edge")
    assert job.attempts == 3
    assert job.latest.id == max(job.attempt_ids)


def test_real_masked_sast_failure_is_flagged(connector, mock_api) -> None:
    """GitLab's own Semgrep analyzer pipeline: a failed SAST job hidden by allow_failure."""
    _, _, report = inspect(connector, mock_api, "semgrep")
    job = next(j for j in report.jobs if j.name == "spotbugs-sast-profile-1")
    assert job.latest.status is JobStatus.FAILED and job.latest.allow_failure
    assert any("spotbugs-sast-profile-1" in w and "allow_failure" in w for w in report.warnings)


def test_real_security_jobs_declare_report_artifacts(connector, mock_api) -> None:
    _, _, report = inspect(connector, mock_api, "semgrep")
    sast = next(j for j in report.jobs if j.name == "semgrep-sast")
    assert {"archive", "sast"} <= {a.file_type for a in sast.latest.artifacts}


def _policy(project_id: int, job: str) -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": project_id},
            "requirements": [
                {
                    "id": "SAST",
                    "tool": "semgrep",
                    "job_name": job,
                    "report_path": "gl-sast-report.json",
                }
            ],
        }
    )


def test_verify_real_pipeline_masked_failure_blocks(connector, mock_api) -> None:
    pipeline, _ = serve(mock_api, "semgrep")
    mock_api.get(url__regex=r".*/artifacts/gl-sast-report\.json").respond(403)
    report = verify_pipeline(
        connector,
        _policy(pipeline["project_id"], "spotbugs-sast-profile-1"),
        instance_url=BASE,
        project=str(pipeline["project_id"]),
        pipeline_id=pipeline["id"],
    )
    assert report.decision is Decision.BLOCKED
    codes = {c.code for c in report.requirements[0].checks}
    assert "FAILURE_MASKED_BY_ALLOW_FAILURE" in codes


def test_verify_real_restricted_artifact_is_indeterminate(connector, mock_api) -> None:
    """What the contract run observed on gitlab.com: security reports are 403 without Developer."""
    pipeline, _ = serve(mock_api, "semgrep")
    mock_api.get(url__regex=r".*/artifacts/gl-sast-report\.json").respond(403)
    report = verify_pipeline(
        connector,
        _policy(pipeline["project_id"], "semgrep-sast"),
        instance_url=BASE,
        project=str(pipeline["project_id"]),
        pipeline_id=pipeline["id"],
    )
    assert report.decision is Decision.INDETERMINATE
    (unknown,) = [c for c in report.requirements[0].checks if c.outcome is Outcome.UNKNOWN]
    assert unknown.code == "EVIDENCE_UNAVAILABLE"
    assert "Developer-role token" in unknown.message
