"""#68: a downstream pipeline that hasn't started yet is not proof that its jobs are absent.

A GitLab trigger (bridge) only gets a downstream pipeline once it runs. While it is created,
pending, waiting or running, every job that pipeline would hold is simply not there yet.
Reporting it as REQUIRED_COPY_ABSENT / REQUIRED_JOB_ABSENT (BLOCKED) asserted a violation that
hadn't happened. It is now INDETERMINATE (JOB_MAYBE_IN_UNREADABLE_PIPELINE). A trigger that
ended without a pipeline (failed, canceled, skipped) or a manual trigger nobody played did not
and will not run its jobs: those stay BLOCKED.
"""

from __future__ import annotations

import pytest

from scanproof.inspection import inspect_pipeline
from scanproof.policy.engine import Decision
from scanproof.verification import verify_pipeline
from tests.conftest import BASE
from tests.fake_gitlab import FakeGitLab
from tests.unit.test_declared_copies import requirement
from tests.unit.test_declared_instances import JOB, REPORT, failing, policy

NOT_STARTED = [
    "created",
    "pending",
    "preparing",
    "waiting_for_resource",
    "scheduled",
    "running",
    "teleporting",  # unrecognized: unknown is never proof of absence
    None,
]
ENDED = ["failed", "canceled", "skipped", "manual", "success"]


def serve_trigger(mock_api, status) -> FakeGitLab:
    gl = FakeGitLab(mock_api)
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.root.children.append(("svc-b", None, status))  # trigger without a downstream pipeline
    gl.install()
    return gl


def verify(connector, req):
    pol = policy("gitlab", "123", req)
    return verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)


@pytest.mark.parametrize("status", NOT_STARTED)
def test_declared_copy_in_unstarted_pipeline_is_unknown(connector, mock_api, status) -> None:
    serve_trigger(mock_api, status)
    report = verify(connector, requirement(JOB, ["svc-a", "svc-b"]))
    assert report.decision is Decision.INDETERMINATE
    assert failing(report) == {f"job_present [svc-b > {JOB}]": "JOB_MAYBE_IN_UNREADABLE_PIPELINE"}


@pytest.mark.parametrize("status", NOT_STARTED)
def test_bare_job_only_in_unstarted_pipeline_is_unknown(connector, mock_api, status) -> None:
    """Predates #65: the same cause gave REQUIRED_JOB_ABSENT for a plain job name."""
    serve_trigger(mock_api, status)
    report = verify(connector, requirement("only-in-svc-b"))
    assert report.decision is Decision.INDETERMINATE
    assert failing(report) == {"job_present": "JOB_MAYBE_IN_UNREADABLE_PIPELINE"}


@pytest.mark.parametrize("status", ENDED)
def test_trigger_that_ended_without_pipeline_is_absent(connector, mock_api, status) -> None:
    serve_trigger(mock_api, status)
    report = verify(connector, requirement(JOB, ["svc-a", "svc-b"]))
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {f"job_present [svc-b > {JOB}]": "REQUIRED_COPY_ABSENT"}


def test_inspection_records_why(connector, mock_api) -> None:
    serve_trigger(mock_api, "running")
    report = inspect_pipeline(connector, instance_url=BASE, project="123", pipeline_id=1042)
    assert report.unreadable_downstream == ["svc-b (not started: running)"]
    assert any("has not started its downstream pipeline yet" in w for w in report.warnings)


def test_present_copies_are_unaffected(connector, mock_api) -> None:
    """A not-started trigger doesn't hide anything that is there: svc-a is still judged."""
    gl = FakeGitLab(mock_api)
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, status="failed", files=REPORT)
    gl.root.children.append(("svc-b", None, "pending"))
    gl.install()
    report = verify(connector, requirement(JOB, ["svc-a", "svc-b"]))
    assert report.decision is Decision.BLOCKED  # a known failure outranks the unknown
    assert failing(report)[f"job_success [svc-a > {JOB}]"] == "JOB_NOT_SUCCESS"
