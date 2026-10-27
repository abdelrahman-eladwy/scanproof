"""#71: a job seen once must not be VERIFIED while an unreadable pipeline may hold another copy.

A bare `job_name` covers every copy of the job, and every copy must pass (#59). A copy in a
downstream pipeline that can't be read (private project, API error, depth limit, or not
started yet, #68) is invisible. Judging only the visible copies made `production` return
VERIFIED although an unseen copy may have failed.

Under `production`, such a requirement is now UNKNOWN (COPIES_UNBOUNDED) unless it declares
`copies`, which bounds the set (`[""]` means only the pipeline's own job is required).
`compatible` keeps its decision and gets a warning. Qualified names ('svc-a > sast') match
only themselves, so they can't have hidden copies and are unaffected.
"""

from __future__ import annotations

import pytest

from scanproof.policy.engine import Decision
from scanproof.policy.models import Policy
from scanproof.policy.profile import assurance_opt_ins
from scanproof.verification import verify_pipeline
from tests.conftest import BASE
from tests.fake_gitlab import FakeGitLab
from tests.unit.test_declared_copies import requirement
from tests.unit.test_declared_instances import JOB, REPORT, failing, policy


def verify(connector, gl, req, profile):
    gl.install()
    pol = policy("gitlab", "123", req, profile)
    return verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)


def root_job_and_private_child(mock_api) -> FakeGitLab:
    gl = FakeGitLab(mock_api)
    gl.job(1, JOB, files=REPORT)
    gl.child("svc-private", project="999", pipeline_id=2100, readable=False)  # 403 on its jobs
    return gl


def test_production_root_job_with_unreadable_child_is_unknown(connector, mock_api) -> None:
    """The #71 case: VERIFIED on main."""
    report = verify(connector, root_job_and_private_child(mock_api), requirement(JOB), "production")
    assert report.decision is Decision.INDETERMINATE
    assert report.exit_code == 2
    assert failing(report) == {"copies_bounded": "COPIES_UNBOUNDED"}
    check = next(c for c in report.requirements[0].checks if c.code == "COPIES_UNBOUNDED")
    assert "svc-private" in check.message and "copies" in check.message


def test_compatible_keeps_decision_and_warns(connector, mock_api) -> None:
    report = verify(connector, root_job_and_private_child(mock_api), requirement(JOB), "compatible")
    assert report.decision is Decision.VERIFIED
    assert any("may have copies in pipelines that could not be read" in w for w in report.warnings)


@pytest.mark.parametrize("copies", [[""], ["", "svc-a"]])
def test_declared_copies_bound_the_set(connector, mock_api, copies) -> None:
    """Declared copies say which are required; an unseen extra one is not required."""
    gl = root_job_and_private_child(mock_api)
    if "svc-a" in copies:
        gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    report = verify(connector, gl, requirement(JOB, copies), "production")
    assert report.decision is Decision.VERIFIED


def test_qualified_name_is_unaffected(connector, mock_api) -> None:
    gl = FakeGitLab(mock_api)
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.child("svc-private", project="999", pipeline_id=2100, readable=False)
    report = verify(connector, gl, requirement(f"svc-a > {JOB}"), "production")
    assert report.decision is Decision.VERIFIED


def test_not_started_child_also_unbounds(connector, mock_api) -> None:
    """#68: a child that hasn't started may still run the job."""
    gl = FakeGitLab(mock_api)
    gl.job(1, JOB, files=REPORT)
    gl.root.children.append(("svc-b", None, "pending"))
    report = verify(connector, gl, requirement(JOB), "production")
    assert failing(report) == {"copies_bounded": "COPIES_UNBOUNDED"}


def test_all_readable_is_unaffected(connector, mock_api) -> None:
    gl = FakeGitLab(mock_api)
    gl.job(1, JOB, files=REPORT)
    gl.child("svc-public", pipeline_id=2000).job(3000, "unrelated", files=REPORT)
    assert verify(connector, gl, requirement(JOB), "production").decision is Decision.VERIFIED


def test_visible_prefixed_copy_reports_undeclared_only(connector, mock_api) -> None:
    """COPIES_UNDECLARED already asks for the same declaration: no second, redundant check."""
    gl = FakeGitLab(mock_api)
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.child("svc-private", project="999", pipeline_id=2100, readable=False)
    report = verify(connector, gl, requirement(JOB), "production")
    assert failing(report) == {"copies_declared": "COPIES_UNDECLARED"}


def test_job_absent_everywhere_is_still_maybe_in_unreadable(connector, mock_api) -> None:
    gl = FakeGitLab(mock_api)
    gl.job(1, "unrelated", files=REPORT)
    gl.child("svc-private", project="999", pipeline_id=2100, readable=False)
    report = verify(connector, gl, requirement(JOB), "production")
    assert failing(report) == {"job_present": "JOB_MAYBE_IN_UNREADABLE_PIPELINE"}


def test_known_failure_still_blocks(connector, mock_api) -> None:
    """A visible failure is a proven violation: BLOCKED outranks the unknown."""
    gl = FakeGitLab(mock_api)
    gl.job(1, JOB, status="failed", files=REPORT)
    gl.child("svc-private", project="999", pipeline_id=2100, readable=False)
    report = verify(connector, gl, requirement(JOB), "production")
    assert report.decision is Decision.BLOCKED
    assert failing(report)["copies_bounded"] == "COPIES_UNBOUNDED"


def test_production_rejects_waiving_copies_bounded() -> None:
    body = policy("gitlab", "1", requirement(JOB)).model_dump(mode="json", exclude_none=True)
    body["enforcement"] = {"max_waiver_days": 30}
    body["waivers"] = [
        {
            "requirement": "SAST",
            "check": "copies_bounded",
            "reason": "accepting hidden copies",
            "approved_by": "lead",
            "expires": "2099-01-01",
            "created": "2098-12-15",
        }
    ]
    codes = [o.code for o in assurance_opt_ins(Policy.model_validate(body))]
    assert "WAIVER_HIDES_UNBOUNDED_COPIES" in codes
    body["assurance"] = {"profile": "production"}
    with pytest.raises(ValueError, match="WAIVER_HIDES_UNBOUNDED_COPIES"):
        Policy.model_validate(body)
