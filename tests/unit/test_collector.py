from __future__ import annotations

import pytest

from scanproof.connectors.base import AuthError
from scanproof.evidence.collector import collect_evidence, find_job
from scanproof.inspection import group_attempts
from scanproof.models import ArtifactFile, Job, JobStatus, Pipeline
from scanproof.scanners.semgrep import SemgrepAdapter
from tests.conftest import API, FIXTURES

SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334"
PIPELINE = Pipeline(id=1042, sha=SHA, status="success")
ARCHIVE = (ArtifactFile(file_type="archive", filename="artifacts.zip", size=100),)


def _job(artifacts=ARCHIVE):
    job = Job(
        id=8821, name="semgrep-sast", status=JobStatus.SUCCESS, commit_sha=SHA, artifacts=artifacts
    )
    return group_attempts([job], SHA)[0]


def _collect(connector, job):
    return collect_evidence(
        connector,
        project="123",
        pipeline=PIPELINE,
        job=job,
        report_path="semgrep.json",
        adapter=SemgrepAdapter(),
    )


URL = f"{API}/projects/123/jobs/8821/artifacts/semgrep.json"


def test_downloads_and_parses(connector, mock_api) -> None:
    mock_api.get(URL).respond(content=(FIXTURES / "semgrep/semgrep-findings.json").read_bytes())
    ev = _collect(connector, _job())

    assert ev.parseable and ev.findings.total == 6
    assert ev.source.job_id == 8821
    assert ev.source.pipeline_sha == SHA
    assert ev.source.job_commit_sha == SHA
    assert ev.source.artifact_path == "semgrep.json"


def test_no_archive_means_missing_without_calling_api(connector, mock_api) -> None:
    route = mock_api.get(URL)
    ev = _collect(connector, _job(artifacts=()))
    assert not ev.present
    assert "no artifacts archive" in ev.parse_error
    assert not route.called


def test_file_not_in_archive_is_missing(connector, mock_api) -> None:
    mock_api.get(URL).respond(404)
    ev = _collect(connector, _job())
    assert not ev.present
    assert "not found in job artifacts" in ev.parse_error


def test_auth_error_is_not_turned_into_missing(connector, mock_api) -> None:
    """403 means we couldn't look - that is UNKNOWN, not 'report missing'."""
    mock_api.get(URL).respond(403)
    with pytest.raises(AuthError) as exc:
        _collect(connector, _job())
    assert "Developer-role token" in str(exc.value)


def test_find_job() -> None:
    jobs = [_job()]
    assert find_job(jobs, "semgrep-sast") is jobs[0]
    assert find_job(jobs, "trivy-image") is None
