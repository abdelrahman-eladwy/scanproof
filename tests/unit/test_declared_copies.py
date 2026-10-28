"""#65: a removed prefixed copy of a required job must not leave the other copies VERIFIED.

A bare `job_name: sast` also matches copies told apart only by a prefix: GitLab downstream
jobs ('svc-a > sast'), GitHub reusable-workflow callers ('api / sast') and Jenkins stage paths
("Scan / Matrix - LANG = 'go' / sast"). Nothing in those names says how many copies there
should be, so deleting a child pipeline's trigger, a calling job or a matrix axis value left
only passing copies: VERIFIED, although part of the code was never scanned. It reproduced
under `assurance.profile: production` too.

A requirement can now declare the copies it needs (`copies: [svc-a, svc-b]`, "" for the
unprefixed job); a declared copy with no job is REQUIRED_COPY_ABSENT. Under production,
prefixed copies without a declaration are UNKNOWN (COPIES_UNDECLARED). Compatible: the old
decision plus a warning.
"""

from __future__ import annotations

import json

import httpx
import pytest

from scanproof.connectors.github import GitHubConnector
from scanproof.connectors.jenkins import JenkinsConnector
from scanproof.evidence.collector import match_jobs
from scanproof.inspection import group_attempts, inspect_pipeline
from scanproof.policy.engine import Decision, Outcome
from scanproof.policy.models import Policy
from scanproof.policy.profile import assurance_opt_ins
from scanproof.verification import verify_pipeline
from tests.conftest import BASE
from tests.fake_github import API, REPO, RUN, FakeGitHub
from tests.fake_gitlab import FakeGitLab
from tests.unit.test_declared_instances import JOB, REPORT, failing, policy
from tests.unit.test_gitlab_real import serve_tree
from tests.unit.test_jenkins import BASE as JENKINS
from tests.unit.test_jenkins import J, serve


def requirement(job: str, copies: list[str] | None = None, **extra) -> dict:
    req = {
        "id": "SAST",
        "tool": "semgrep",
        "job_name": job,
        "report_path": "semgrep.json",
        "checks": {"scanner_errors_allowed": 0, "minimum_scanned_files": 1},
        **extra,
    }
    if copies is not None:
        req["copies"] = copies
    return req


# ---------------------------------------------------------------- GitLab downstream


@pytest.fixture
def gl(mock_api) -> FakeGitLab:
    return FakeGitLab(mock_api)


def gitlab_verify(connector, gl, copies=None, *, profile="compatible", **extra):
    gl.install()
    pol = policy("gitlab", "123", requirement(JOB, copies, **extra), profile)
    return verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)


@pytest.mark.parametrize("profile", ["compatible", "production"])
def test_gitlab_removed_child_pipeline_fails_when_declared(connector, gl, profile) -> None:
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)  # svc-b's trigger removed
    report = gitlab_verify(connector, gl, ["svc-a", "svc-b"], profile=profile)
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {f"job_present [svc-b > {JOB}]": "REQUIRED_COPY_ABSENT"}
    check = next(c for c in report.requirements[0].checks if c.code == "REQUIRED_COPY_ABSENT")
    assert "Declared copy 'svc-b'" in check.message


def test_gitlab_removed_child_without_declaration_is_unchanged(connector, gl) -> None:
    """Compatible: the old outcome, plus a warning that the copy set is not checked."""
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    report = gitlab_verify(connector, gl)
    assert report.decision is Decision.VERIFIED
    assert any("declares no `copies`" in w for w in report.warnings)


def test_gitlab_production_requires_declaration_for_prefixed_copies(connector, gl) -> None:
    """The original false VERIFIED (#65) under production: now INDETERMINATE, exit 2."""
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    report = gitlab_verify(connector, gl, profile="production")
    assert report.decision is Decision.INDETERMINATE
    assert report.exit_code == 2
    assert failing(report) == {"copies_declared": "COPIES_UNDECLARED"}


def test_gitlab_production_with_declaration_verifies(connector, gl) -> None:
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.child("svc-b", pipeline_id=2001).job(3001, JOB, files=REPORT)
    report = gitlab_verify(connector, gl, ["svc-a", "svc-b"], profile="production")
    assert report.decision is Decision.VERIFIED


def test_gitlab_production_plain_job_needs_no_declaration(connector, gl) -> None:
    gl.job(1, JOB, files=REPORT)
    assert gitlab_verify(connector, gl, profile="production").decision is Decision.VERIFIED


def test_gitlab_removed_root_copy_fails(connector, gl) -> None:
    """'' is the pipeline's own job: removing it while a child still runs one is caught."""
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    report = gitlab_verify(connector, gl, ["", "svc-a"])
    assert failing(report) == {f"job_present [{JOB}]": "REQUIRED_COPY_ABSENT"}
    check = next(c for c in report.requirements[0].checks if c.code == "REQUIRED_COPY_ABSENT")
    assert "the pipeline itself" in check.message


def test_gitlab_nested_child_copy(connector, gl) -> None:
    child = gl.child("deploy", pipeline_id=2000)
    child.child("svc-a", pipeline_id=2100).job(3000, JOB, files=REPORT)
    report = gitlab_verify(connector, gl, ["deploy > svc-a", "deploy > svc-b"])
    assert failing(report) == {f"job_present [deploy > svc-b > {JOB}]": "REQUIRED_COPY_ABSENT"}


def test_gitlab_extra_copy_is_allowed_and_still_checked(connector, gl) -> None:
    gl.job(1, JOB, files=REPORT)
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, status="failed", files=REPORT)
    report = gitlab_verify(connector, gl, [""])
    assert failing(report) == {f"job_success [svc-a > {JOB}]": "JOB_NOT_SUCCESS"}


def test_gitlab_single_declared_copy_present_verifies(connector, gl) -> None:
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    report = gitlab_verify(connector, gl, ["svc-a"], profile="production")
    assert report.decision is Decision.VERIFIED
    assert report.requirements[0].job_id == 3000  # the single-job path


def test_gitlab_missing_copy_with_unreadable_pipeline_is_unknown(connector, gl) -> None:
    """The missing copy may be the pipeline that couldn't be read: not proven absent."""
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.child("svc-b", pipeline_id=2001, readable=False)  # its jobs endpoint returns 403
    report = gitlab_verify(connector, gl, ["svc-a", "svc-b"])
    assert failing(report) == {f"job_present [svc-b > {JOB}]": "JOB_MAYBE_IN_UNREADABLE_PIPELINE"}
    assert report.decision is Decision.INDETERMINATE


@pytest.mark.parametrize("copies", [["svc-a", "svc-b"], ["svc-b"], [""]])
def test_unrelated_private_child_does_not_hide_removed_copy(connector, gl, copies) -> None:
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.child("svc-private", pipeline_id=2001, readable=False)
    report = gitlab_verify(connector, gl, copies, profile="production")
    assert report.decision is Decision.BLOCKED
    assert "JOB_MAYBE_IN_UNREADABLE_PIPELINE" not in failing(report).values()


def test_private_ancestor_keeps_declared_nested_copy_unknown(connector, gl) -> None:
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.child("deploy", pipeline_id=2001, readable=False)
    report = gitlab_verify(connector, gl, ["svc-a", "deploy > svc-b"])
    assert report.decision is Decision.INDETERMINATE


def test_no_visible_match_with_unrelated_private_child_is_blocked(connector, gl) -> None:
    gl.child("svc-private", pipeline_id=2001, readable=False)
    report = gitlab_verify(connector, gl, ["svc-b"], profile="production")
    assert report.decision is Decision.BLOCKED


@pytest.mark.parametrize("on_unknown", ["block", "warn"])
def test_no_match_absent_copy_is_not_hidden_by_unreadable_declared_copy(
    connector, gl, on_unknown
) -> None:
    """No copy ran: svc-a's trigger was removed (proven), svc-private can't be read. The
    proven absence must BLOCK; before, the whole requirement became UNKNOWN and on_unknown:
    warn turned it into VERIFIED."""
    gl.child("svc-private", pipeline_id=2001, readable=False)
    gl.install()
    body = policy("gitlab", "123", requirement(JOB, ["svc-a", "svc-private"])).model_dump()
    body["enforcement"]["on_unknown"] = on_unknown
    report = verify_pipeline(
        connector, Policy.model_validate(body), instance_url=BASE, project="123", pipeline_id=1042
    )
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {
        f"job_present [svc-a > {JOB}]": "REQUIRED_COPY_ABSENT",
        f"job_present [svc-private > {JOB}]": "JOB_MAYBE_IN_UNREADABLE_PIPELINE",
    }


def test_bare_missing_job_remains_unknown_with_private_child(connector, gl) -> None:
    gl.child("svc-private", pipeline_id=2001, readable=False)
    report = gitlab_verify(connector, gl, profile="production")
    assert report.decision is Decision.INDETERMINATE


def test_similar_private_prefix_does_not_hide_removed_copy(connector, gl) -> None:
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.child("svc-b-extra", pipeline_id=2001, readable=False)
    report = gitlab_verify(connector, gl, ["svc-a", "svc-b"])
    assert report.decision is Decision.BLOCKED


def test_unrelated_private_child_cannot_downgrade_failure_with_on_unknown_warn(
    connector, gl
) -> None:
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.child("svc-private", pipeline_id=2001, readable=False)
    gl.install()
    body = policy("gitlab", "123", requirement(JOB, ["svc-a", "svc-b"])).model_dump()
    body["enforcement"]["on_unknown"] = "warn"
    pol = Policy.model_validate(body)
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {f"job_present [svc-b > {JOB}]": "REQUIRED_COPY_ABSENT"}


@pytest.mark.parametrize("path", [f"svc-b > {JOB}", f"svc-private > {JOB}"])
def test_qualified_missing_job_uses_its_own_subtree(connector, gl, path) -> None:
    gl.child("svc-private", pipeline_id=2001, readable=False)
    gl.install()
    pol = policy("gitlab", "123", requirement(path), "production")
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    expected = Decision.INDETERMINATE if path.startswith("svc-private > ") else Decision.BLOCKED
    assert report.decision is expected


@pytest.mark.parametrize("status", [403, 429])
def test_declared_public_copies_with_unrelated_unreadable_child_verify(
    connector, gl, mock_api, status
) -> None:
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.child("svc-b", pipeline_id=2001).job(3001, JOB, files=REPORT)
    gl.child("svc-private", pipeline_id=2002, readable=False)
    gl.install()
    mock_api.get(f"{BASE}/api/v4/projects/123/pipelines/2002/jobs").respond(status)
    pol = policy("gitlab", "123", requirement(JOB, ["svc-a", "svc-b"]), "production")
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    assert report.decision is Decision.VERIFIED
    assert any("could not be read" in w for w in report.warnings)


def test_public_children_rate_limited_reproduces_live_unknown(connector, gl, mock_api) -> None:
    for i, svc in enumerate(["svc-a", "svc-b", "svc-private"]):
        gl.child(svc, pipeline_id=2000 + i, readable=False)
    gl.install()
    for pid in (2000, 2001, 2002):
        mock_api.get(f"{BASE}/api/v4/projects/123/pipelines/{pid}/jobs").respond(429)
    pol = policy("gitlab", "123", requirement(JOB, ["svc-a", "svc-b"]), "production")
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    assert report.decision is Decision.INDETERMINATE
    assert failing(report) == {
        f"job_present [svc-a > {JOB}]": "JOB_MAYBE_IN_UNREADABLE_PIPELINE",
        f"job_present [svc-b > {JOB}]": "JOB_MAYBE_IN_UNREADABLE_PIPELINE",
    }
    assert all("RATE_LIMITED" in w for w in report.warnings if "could not be read" in w)


def test_root_trigger_inventory_failure_keeps_missing_child_unknown(connector, gl, mock_api):
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.install()
    mock_api.routes["bridges"].respond(429)
    pol = policy("gitlab", "123", requirement(JOB, ["svc-b"]), "production")
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    assert report.decision is Decision.INDETERMINATE


def test_depth_limit_keeps_nested_copy_unknown(connector, gl, monkeypatch):
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.child("deploy", pipeline_id=2001)
    monkeypatch.setattr("scanproof.inspection.MAX_DOWNSTREAM_DEPTH", 0)
    report = gitlab_verify(connector, gl, ["deploy > svc-b"])
    assert report.decision is Decision.INDETERMINATE


def test_count_limit_keeps_declared_copy_unknown(connector, gl, monkeypatch):
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    monkeypatch.setattr("scanproof.inspection.MAX_DOWNSTREAM_PIPELINES", 1)
    report = gitlab_verify(connector, gl, ["svc-a"])
    assert report.decision is Decision.INDETERMINATE


@pytest.mark.parametrize("copy", ["deploy", "deploy > svc-b"])
def test_unreadable_child_trigger_inventory_only_hides_descendants(connector, gl, mock_api, copy):
    gl.child("deploy", pipeline_id=2000)  # its own job list is readable and empty
    gl.install()
    mock_api.routes["bridges"].mock(
        side_effect=lambda request: (
            httpx.Response(429)
            if request.url.path.endswith("/2000/bridges")
            else httpx.Response(
                200,
                json=[
                    {
                        "name": "deploy",
                        "status": "success",
                        "downstream_pipeline": {"id": 2000, "project_id": 123},
                    }
                ],
            )
        )
    )
    pol = policy("gitlab", "123", requirement(JOB, [copy]), "production")
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    assert report.decision is (Decision.BLOCKED if copy == "deploy" else Decision.INDETERMINATE)


def test_gitlab_trigger_that_created_no_pipeline_is_absent(connector, gl) -> None:
    """A failed trigger (no child pipeline) is not unreadable: the copy did not run."""
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.failed_trigger("svc-b")
    report = gitlab_verify(connector, gl, ["svc-a", "svc-b"])
    assert failing(report) == {f"job_present [svc-b > {JOB}]": "REQUIRED_COPY_ABSENT"}


def test_gitlab_copies_and_instances_every_copy_runs_every_leg(connector, gl) -> None:
    svc_a = gl.child("svc-a", pipeline_id=2000)
    svc_a.job(3000, f"{JOB}: [py]", files=REPORT)
    svc_a.job(3001, f"{JOB}: [js]", files=REPORT)
    gl.child("svc-b", pipeline_id=2001).job(3100, JOB, files=REPORT)  # not a matrix any more
    report = gitlab_verify(connector, gl, ["svc-a", "svc-b"], instances=["py", "js"])
    assert failing(report) == {
        f"job_present [svc-b > {JOB}: [py]]": "REQUIRED_INSTANCE_ABSENT",
        f"job_present [svc-b > {JOB}: [js]]": "REQUIRED_INSTANCE_ABSENT",
    }


def test_gitlab_qualified_job_name_is_unaffected(connector, gl) -> None:
    """'svc-a > sast' matches only itself; production needs no copies for it."""
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.install()
    pol = policy("gitlab", "123", requirement(f"svc-a > {JOB}"), "production")
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    assert report.decision is Decision.VERIFIED


def test_waiving_the_absent_copy_is_still_a_visible_waiver(connector, gl) -> None:
    """Not a silent pass: the compatible profile allows the waiver, production rejects it."""
    body = policy("gitlab", "123", requirement(JOB, ["svc-a", "svc-b"])).model_dump(
        mode="json", exclude_none=True
    )
    body["waivers"] = [
        {
            "requirement": "SAST",
            "check": f"job_present [svc-b > {JOB}]",
            "reason": "svc-b retired in TICKET-1",
            "approved_by": "lead",
            "expires": "2099-01-01",
        }
    ]
    codes = [o.code for o in assurance_opt_ins(Policy.model_validate(body))]
    assert "WAIVER_REMOVES_REQUIREMENT" in codes


# ---------------------------------------------------------------- GitHub reusable callers


@pytest.fixture
def gh(mock_api) -> FakeGitHub:
    return FakeGitHub(mock_api)


@pytest.fixture
def conn(sleeps):
    with GitHubConnector(API, "ghp_test", sleep=sleeps.append, max_retries=1) as c:
        yield c


def github_verify(conn, gh, copies=None, *, profile="compatible", **extra):
    req = requirement("sast", copies, artifact_name="scan-report", **extra)
    gh.artifact(10, "scan-report", REPORT)
    gh.install()
    pol = policy("github", REPO, req, profile)
    return verify_pipeline(conn, pol, instance_url=API, project=REPO, pipeline_id=RUN)


def test_github_removed_reusable_caller_fails_when_declared(conn, gh) -> None:
    gh.job(1, "api / sast")  # the 'web' caller was removed
    report = github_verify(conn, gh, ["api", "web"])
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {"job_present [web / sast]": "REQUIRED_COPY_ABSENT"}


def test_github_production_requires_declaration_for_callers(conn, gh) -> None:
    gh.job(1, "api / sast")
    report = github_verify(conn, gh, profile="production")
    assert report.decision is Decision.INDETERMINATE
    assert failing(report) == {"copies_declared": "COPIES_UNDECLARED"}


def test_github_production_with_declaration_verifies(conn, gh) -> None:
    gh.job(1, "api / sast")
    gh.job(2, "web / sast")
    assert github_verify(conn, gh, ["api", "web"], profile="production").decision is (
        Decision.VERIFIED
    )


def test_github_caller_running_a_matrix(conn, gh) -> None:
    gh.job(1, "api / sast (py)")
    gh.job(2, "web / sast (js)")  # web lost its py leg
    report = github_verify(conn, gh, ["api", "web"], instances=["py", "js"], profile="production")
    assert failing(report) == {
        "job_present [api / sast (js)]": "REQUIRED_INSTANCE_ABSENT",
        "job_present [web / sast (py)]": "REQUIRED_INSTANCE_ABSENT",
    }


# ---------------------------------------------------------------- Jenkins (real responses)


@pytest.fixture
def jenkins(sleeps):
    with JenkinsConnector(JENKINS, "api-token", username="scanproof", sleep=sleeps.append) as c:
        yield c


GO = "Scan / Matrix - LANG = 'go'"
PY = "Scan / Matrix - LANG = 'python'"


def jenkins_policy(copies=None, profile="compatible") -> Policy:
    req = requirement("sast", copies, report_path="python/semgrep.json")
    req["checks"] = {"same_commit": False}  # the contract jobs have no SCM checkout
    return policy("jenkins", "sast-matrix", req, profile)


def without_go(mock_api) -> None:
    """The real build, with the 'go' axis value removed from the matrix."""
    tree = json.loads((J / "sast-matrix/stages_tree.json").read_text())
    for stage in tree["data"]["stages"]:
        stage["children"] = [c for c in stage.get("children", []) if "'go'" not in c["name"]]
    mock_api.get(f"{JENKINS}/job/sast-matrix/1/stages/tree").respond(json=tree)


def test_jenkins_real_matrix_stage_paths_are_copies(jenkins, mock_api) -> None:
    serve(mock_api, "sast-matrix")
    jobs = jenkins.list_jobs("sast-matrix", 1)
    match = match_jobs(_inspected(jobs), "sast", copies=[GO, PY])
    assert match.missing_copies == []


def test_jenkins_removed_matrix_stage_fails_when_declared(jenkins, mock_api) -> None:
    serve(mock_api, "sast-matrix")
    without_go(mock_api)
    report = verify_pipeline(
        jenkins,
        jenkins_policy([GO, PY]),
        instance_url=JENKINS,
        project="sast-matrix",
        pipeline_id=1,
    )
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {f"job_present [{GO} / sast]": "REQUIRED_COPY_ABSENT"}


def test_jenkins_removed_matrix_stage_production_is_unknown(jenkins, mock_api) -> None:
    """Production keeps same_commit on; these contract jobs report no commit (UNKNOWN too)."""
    serve(mock_api, "sast-matrix")
    without_go(mock_api)
    pol = policy(
        "jenkins",
        "sast-matrix",
        requirement("sast", report_path="python/semgrep.json"),
        "production",
    )
    report = verify_pipeline(
        jenkins, pol, instance_url=JENKINS, project="sast-matrix", pipeline_id=1
    )
    assert report.decision is Decision.INDETERMINATE
    assert failing(report)["copies_declared"] == "COPIES_UNDECLARED"


def _inspected(jobs):
    return group_attempts(jobs, pipeline_sha="0" * 40)


# ---------------------------------------------------------------- real GitLab names


def test_real_gitlab_child_pipeline_names_are_copies(connector, mock_api) -> None:
    """Real gitlab-org/gitlab parent/child responses, through the real inspection path."""
    pipeline = serve_tree(mock_api, "gitlab")
    jobs = inspect_pipeline(
        connector,
        instance_url=BASE,
        project=str(pipeline["project_id"]),
        pipeline_id=pipeline["id"],
    ).jobs
    trigger = "rspec-ee:predictive:trigger"
    name = "rspec-ee unit predictive"
    assert f"{trigger} > {name}" in {j.name for j in jobs}

    match = match_jobs(jobs, name)
    assert match.undeclared_copies == [f"{trigger} > {name}"]
    assert match_jobs(jobs, name, copies=[trigger]).missing_copies == []
    # A second child that used to run the same job, now removed:
    assert match_jobs(jobs, name, copies=[trigger, "rspec-ee:other:trigger"]).missing_copies == [
        (f"rspec-ee:other:trigger > {name}", "rspec-ee:other:trigger")
    ]
    # The trigger itself removed: every job of that child disappears with it.
    gone = [j for j in jobs if not j.name.startswith(f"{trigger} > ")]
    assert match_jobs(gone, name, copies=[trigger]).jobs == []


# ---------------------------------------------------------------- policy field and profile


def load_with(copies):
    return policy("gitlab", "1", requirement(JOB, copies))


def test_paths_are_stored_stripped() -> None:
    assert load_with([" svc-a ", "", "Scan / Matrix - X"]).requirements[0].copies == [
        "svc-a",
        "",
        "Scan / Matrix - X",
    ]


@pytest.mark.parametrize(
    ("copies", "error"),
    [
        ([], "at least one path"),
        (["svc-a", " svc-a"], "twice"),
        (["", " "], "twice"),
        (["svc-a >"], "separator"),
        (["caller /"], "separator"),
    ],
)
def test_bad_declarations_are_load_errors(copies, error) -> None:
    with pytest.raises(ValueError, match=error):
        load_with(copies)


def test_production_rejects_waiving_copies_declared() -> None:
    body = load_with(None).model_dump(mode="json", exclude_none=True)
    body["enforcement"] = {"max_waiver_days": 30}
    body["waivers"] = [
        {
            "requirement": "SAST",
            "check": "copies_declared",
            "code": "COPIES_UNDECLARED",
            "reason": "accepting unchecked copies",
            "approved_by": "lead",
            "expires": "2099-01-01",
            "created": "2098-12-15",
        }
    ]
    assert "WAIVER_HIDES_UNDECLARED_COPIES" in [
        o.code for o in assurance_opt_ins(Policy.model_validate(body))
    ]
    body["assurance"] = {"profile": "production"}
    with pytest.raises(ValueError, match="WAIVER_HIDES_UNDECLARED_COPIES"):
        Policy.model_validate(body)


def test_copies_declared_is_not_a_pass_without_jobs(connector, gl) -> None:
    """Every copy gone: each declared copy is absent (never VERIFIED)."""
    gl.job(1, "unrelated", files=REPORT)
    report = gitlab_verify(connector, gl, ["svc-a"])
    assert failing(report) == {f"job_present [svc-a > {JOB}]": "REQUIRED_COPY_ABSENT"}
    assert all(c.outcome is not Outcome.PASS for c in report.requirements[0].checks)


# ---------------------------------------------------------------- root trigger list 404 (#44)


def _root_bridges_404(gl, mock_api) -> None:
    """A failing child copy exists, but the root's trigger list answers 404."""
    gl.job(1, JOB, files=REPORT)
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, status="failed", files=REPORT)
    gl.install()
    mock_api.routes["bridges"].respond(404)


def test_root_bridges_404_cannot_hide_a_failing_child_in_production(connector, gl, mock_api):
    """Was VERIFIED: the 404 was read as 'no child pipelines', so the failing
    'svc-a > semgrep-sast' was never seen next to the passing root job."""
    _root_bridges_404(gl, mock_api)
    pol = policy("gitlab", "123", requirement(JOB), "production")
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    assert report.decision is Decision.INDETERMINATE
    assert set(failing(report).values()) == {"COPIES_UNBOUNDED"}


def test_root_bridges_404_is_reported_in_compatible(connector, gl, mock_api):
    _root_bridges_404(gl, mock_api)
    pol = policy("gitlab", "123", requirement(JOB))
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    assert any("could not be read" in w or "unreadable" in w.lower() for w in report.warnings)


def test_root_bridges_404_keeps_a_declared_child_copy_unknown(connector, gl, mock_api):
    _root_bridges_404(gl, mock_api)
    pol = policy("gitlab", "123", requirement(JOB, ["", "svc-a"]))
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    assert failing(report) == {f"job_present [svc-a > {JOB}]": "JOB_MAYBE_IN_UNREADABLE_PIPELINE"}


def test_root_bridges_404_still_proves_root_jobs(connector, gl, mock_api):
    """The root's own job list was read: a missing root copy is still a proven FAIL."""
    gl.child("svc-a", pipeline_id=2000).job(3000, JOB, files=REPORT)
    gl.job(1, "other", files=REPORT)
    gl.install()
    mock_api.routes["bridges"].respond(404)
    pol = policy("gitlab", "123", requirement(JOB, [""]))
    report = verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {f"job_present [{JOB}]": "REQUIRED_COPY_ABSENT"}
