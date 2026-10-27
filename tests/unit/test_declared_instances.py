"""#60: a removed matrix leg must not leave the remaining legs VERIFIED.

GitLab `parallel: N` legs are named 'sast 2/3', so a missing index is visible. Matrix legs
(GitLab `parallel: matrix:` 'sast: [py]', GitHub `strategy.matrix` 'sast (py)') carry no total:
dropping `js` from the matrix leaves only passing legs, and nothing in the job names says a leg
is gone. A requirement can now declare the legs it needs (`instances: [py, js]`); a declared
label without a leg is REQUIRED_INSTANCE_ABSENT.

Compatibility: a requirement without `instances` behaves exactly as before (plus a warning that
the leg set is unchecked). Under `assurance.profile: production`, matrix legs without a
declaration are UNKNOWN (INSTANCES_UNDECLARED): the gap is reported, never silently passed.
"""

from __future__ import annotations

import json

import pytest

from scanproof.connectors.github import GitHubConnector
from scanproof.connectors.gitlab import _parse_job
from scanproof.evidence.collector import find_jobs, match_jobs
from scanproof.inspection import group_attempts
from scanproof.models import normalize_instance_label
from scanproof.policy.engine import Decision, Outcome
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.conftest import BASE, FIXTURES
from tests.fake_github import API, REPO, RUN, FakeGitHub
from tests.fake_gitlab import FakeGitLab

SEMGREP = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()
REPORT = {"semgrep.json": SEMGREP}
JOB = "semgrep-sast"


def failing(report) -> dict[str, str]:
    return {c.check: c.code for c in report.requirements[0].checks if c.outcome is not Outcome.PASS}


def requirement(job: str, instances: list[str] | None, **extra) -> dict:
    req = {
        "id": "SAST",
        "tool": "semgrep",
        "job_name": job,
        "report_path": "semgrep.json",
        "checks": {"scanner_errors_allowed": 0, "minimum_scanned_files": 1},
        **extra,
    }
    if instances is not None:
        req["instances"] = instances
    return req


def policy(provider: str, project: str, req: dict, profile: str = "compatible") -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": provider, "id": project},
            "assurance": {"profile": profile},
            "requirements": [req],
        }
    )


# ---------------------------------------------------------------- GitLab


@pytest.fixture
def gl(mock_api) -> FakeGitLab:
    return FakeGitLab(mock_api)


def gitlab_verify(connector, gl, instances=None, *, profile="compatible", job=JOB):
    gl.install()
    pol = policy("gitlab", "123", requirement(job, instances), profile)
    return verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)


def test_gitlab_removed_matrix_leg_fails_when_declared(connector, gl) -> None:
    gl.job(1, f"{JOB}: [py]", files=REPORT)
    gl.job(2, f"{JOB}: [go]", files=REPORT)  # `js` was dropped from parallel: matrix:
    report = gitlab_verify(connector, gl, ["py", "js", "go"])
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {f"job_present [{JOB}: [js]]": "REQUIRED_INSTANCE_ABSENT"}
    check = next(c for c in report.requirements[0].checks if c.code == "REQUIRED_INSTANCE_ABSENT")
    assert "Declared instance 'js'" in check.message


def test_gitlab_removed_leg_without_declaration_is_unchanged(connector, gl) -> None:
    """Compatible: the old outcome, plus a warning that the leg set is not checked."""
    gl.job(1, f"{JOB}: [py]", files=REPORT)
    gl.job(2, f"{JOB}: [go]", files=REPORT)
    report = gitlab_verify(connector, gl)
    assert report.decision is Decision.VERIFIED
    assert any("declares no `instances`" in w for w in report.warnings)


def test_gitlab_single_remaining_leg_fails_when_declared(connector, gl) -> None:
    """One job left: the single-job path must still see the declared, missing leg."""
    gl.job(1, f"{JOB}: [py]", files=REPORT)
    report = gitlab_verify(connector, gl, ["py", "js"])
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {f"job_present [{JOB}: [js]]": "REQUIRED_INSTANCE_ABSENT"}


def test_gitlab_multi_variable_labels_are_normalized(connector, gl) -> None:
    gl.job(1, f"{JOB}: [amd64, x86_64]", files=REPORT)
    report = gitlab_verify(connector, gl, ["amd64,x86_64", "arm64, arm64"])
    assert failing(report) == {f"job_present [{JOB}: [arm64, arm64]]": "REQUIRED_INSTANCE_ABSENT"}


def test_gitlab_all_declared_legs_and_an_extra_leg_verify(connector, gl) -> None:
    """Extra legs are allowed, and still have to pass."""
    gl.job(1, f"{JOB}: [py]", files=REPORT)
    gl.job(2, f"{JOB}: [js]", files=REPORT)
    gl.job(3, f"{JOB}: [go]", files=REPORT)
    report = gitlab_verify(connector, gl, ["py", "js"])
    assert report.decision is Decision.VERIFIED
    assert not any("instances" in w for w in report.warnings)


def test_gitlab_failing_extra_leg_still_blocks(connector, gl) -> None:
    gl.job(1, f"{JOB}: [py]", files=REPORT)
    gl.job(2, f"{JOB}: [js]", files=REPORT)
    gl.job(3, f"{JOB}: [go]", status="failed", files=REPORT)
    report = gitlab_verify(connector, gl, ["py", "js"])
    assert failing(report) == {f"job_success [{JOB}: [go]]": "JOB_NOT_SUCCESS"}


def test_gitlab_matrix_replaced_by_plain_job_misses_every_leg(connector, gl) -> None:
    gl.job(1, JOB, files=REPORT)
    report = gitlab_verify(connector, gl, ["py", "js"])
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {
        f"job_present [{JOB} [py]]": "REQUIRED_INSTANCE_ABSENT",
        f"job_present [{JOB} [js]]": "REQUIRED_INSTANCE_ABSENT",
    }


def test_gitlab_declared_job_absent_is_still_required_job_absent(connector, gl) -> None:
    gl.job(1, "unrelated", files=REPORT)
    report = gitlab_verify(connector, gl, ["py"])
    assert failing(report) == {"job_present": "REQUIRED_JOB_ABSENT"}


def test_gitlab_downstream_legs_are_checked_per_pipeline(connector, gl) -> None:
    """Each pipeline that runs the matrix must run every declared leg."""
    gl.job(1, f"{JOB}: [py]", files=REPORT)
    gl.job(2, f"{JOB}: [js]", files=REPORT)
    gl.child("trigger", pipeline_id=2000).job(3000, f"{JOB}: [py]", files=REPORT)
    report = gitlab_verify(connector, gl, ["py", "js"])
    assert failing(report) == {f"job_present [trigger > {JOB}: [js]]": "REQUIRED_INSTANCE_ABSENT"}


@pytest.mark.parametrize("instances", [None, ["py", "js"]])
def test_gitlab_parallel_missing_index_is_unchanged(connector, gl, instances) -> None:
    """`parallel: N` names carry the total; the missing index is still REQUIRED_JOB_ABSENT."""
    gl.job(1, f"{JOB} 1/3", files=REPORT)
    gl.job(2, f"{JOB} 3/3", files=REPORT)
    report = gitlab_verify(connector, gl, instances)
    assert report.decision is Decision.BLOCKED
    expected = {f"job_present [{JOB} 2/3]": "REQUIRED_JOB_ABSENT"}
    if instances:  # declaring matrix labels on a parallel: N job: no leg carries them
        expected |= {f"job_present [{JOB} [{x}]]": "REQUIRED_INSTANCE_ABSENT" for x in instances}
    assert failing(report) == expected


def test_gitlab_parallel_complete_needs_no_declaration_in_production(connector, gl) -> None:
    gl.job(1, f"{JOB} 1/2", files=REPORT)
    gl.job(2, f"{JOB} 2/2", files=REPORT)
    report = gitlab_verify(connector, gl, profile="production")
    assert report.decision is Decision.VERIFIED


def test_gitlab_production_requires_declaration_for_matrix_legs(connector, gl) -> None:
    gl.job(1, f"{JOB}: [py]", files=REPORT)
    report = gitlab_verify(connector, gl, profile="production")
    assert report.decision is Decision.INDETERMINATE
    assert failing(report) == {"instances_declared": "INSTANCES_UNDECLARED"}
    assert report.exit_code == 2


def test_gitlab_production_with_declaration_verifies(connector, gl) -> None:
    gl.job(1, f"{JOB}: [py]", files=REPORT)
    gl.job(2, f"{JOB}: [js]", files=REPORT)
    report = gitlab_verify(connector, gl, ["py", "js"], profile="production")
    assert report.decision is Decision.VERIFIED


def test_gitlab_production_plain_job_needs_no_declaration(connector, gl) -> None:
    gl.job(1, JOB, files=REPORT)
    assert gitlab_verify(connector, gl, profile="production").decision is Decision.VERIFIED


# ---------------------------------------------------------------- GitHub


@pytest.fixture
def gh(mock_api) -> FakeGitHub:
    return FakeGitHub(mock_api)


@pytest.fixture
def conn(sleeps):
    with GitHubConnector(API, "ghp_test", sleep=sleeps.append, max_retries=1) as c:
        yield c


def github_verify(conn, gh, instances=None, *, profile="compatible"):
    req = requirement("sast", instances, artifact_name="scan-report")
    gh.artifact(10, "scan-report", REPORT)
    gh.install()
    pol = policy("github", REPO, req, profile)
    return verify_pipeline(conn, pol, instance_url=API, project=REPO, pipeline_id=RUN)


def test_github_removed_matrix_leg_fails_when_declared(conn, gh) -> None:
    gh.job(1, "sast (py)")
    gh.job(2, "sast (go)")  # `js` was dropped from strategy.matrix
    report = github_verify(conn, gh, ["py", "js", "go"])
    assert report.decision is Decision.BLOCKED
    assert failing(report) == {"job_present [sast (js)]": "REQUIRED_INSTANCE_ABSENT"}


def test_github_removed_leg_without_declaration_is_unchanged(conn, gh) -> None:
    gh.job(1, "sast (py)")
    gh.job(2, "sast (go)")
    report = github_verify(conn, gh)
    assert report.decision is Decision.VERIFIED
    assert any("declares no `instances`" in w for w in report.warnings)


def test_github_multi_variable_leg(conn, gh) -> None:
    gh.job(1, "sast (py, 3.12)")
    report = github_verify(conn, gh, ["py, 3.12", "py, 3.13"])
    assert failing(report) == {"job_present [sast (py, 3.13)]": "REQUIRED_INSTANCE_ABSENT"}


def test_github_reusable_workflow_legs(conn, gh) -> None:
    """A matrix inside a reusable workflow: 'caller / sast (py)'."""
    gh.job(1, "security / sast (py)")
    report = github_verify(conn, gh, ["py", "js"])
    assert failing(report) == {"job_present [security / sast (js)]": "REQUIRED_INSTANCE_ABSENT"}


def test_github_production_requires_declaration(conn, gh) -> None:
    gh.job(1, "sast (py)")
    gh.job(2, "sast (go)")
    report = github_verify(conn, gh, profile="production")
    assert report.decision is Decision.INDETERMINATE
    assert failing(report) == {"instances_declared": "INSTANCES_UNDECLARED"}


def test_github_production_with_declaration_verifies(conn, gh) -> None:
    gh.job(1, "sast (py)")
    gh.job(2, "sast (go)")
    assert github_verify(conn, gh, ["py", "go"], profile="production").decision is (
        Decision.VERIFIED
    )


# ---------------------------------------------------------------- real GitLab job names


def real_gitlab_jobs(fixture: str = "children/gitlab-runner"):
    raw = json.loads((FIXTURES / f"gitlab-real/{fixture}/jobs.json").read_text())
    return group_attempts([_parse_job(item) for item in raw], pipeline_sha="0" * 40)


@pytest.mark.parametrize(
    ("fixture", "name", "labels"),
    [
        (
            "children/gitlab-runner",
            "package-deb",
            ["deb32", "deb64", "debArm32", "debArm64", "debIbm", "debLoong64", "debRiscv64"],
        ),
        ("cli", "windows_installer", ["amd64, x86_64", "arm64, arm64"]),
        (
            "children/gitlab-runner",
            "helper images",  # one value containing spaces
            ["alpine alpine-pwsh ubuntu ubuntu-pwsh ubi-fips concrete"],
        ),
    ],
)
def test_real_gitlab_matrix_names_match_their_labels(fixture, name, labels) -> None:
    jobs = real_gitlab_jobs(fixture)
    match = match_jobs(jobs, name, labels)
    assert len(match.jobs) >= len(labels)
    assert match.missing_declared == []
    # Remove one real leg: the declaration now reports exactly that one.
    removed = next(j for j in jobs if j.name == f"{name}: [{labels[0]}]")
    match = match_jobs([j for j in jobs if j is not removed], name, labels)
    assert match.missing_declared == [(f"{name}: [{labels[0]}]", labels[0])]


def test_find_jobs_signature_is_unchanged() -> None:
    jobs = real_gitlab_jobs()
    matches, missing = find_jobs(jobs, "package-deb")
    assert len(matches) == 7 and missing == []


def test_undeclared_legs_are_listed_only_for_matrix_names() -> None:
    jobs = real_gitlab_jobs()
    assert len(match_jobs(jobs, "package-deb").undeclared_legs) == 7
    assert match_jobs(jobs, "package-deb", ["deb32"]).undeclared_legs == []


# ---------------------------------------------------------------- policy field


def load_with(instances):
    return policy("gitlab", "1", requirement(JOB, instances))


def test_labels_are_stored_normalized() -> None:
    assert load_with(["py ,3.12", " js "]).requirements[0].instances == ["py, 3.12", "js"]
    assert normalize_instance_label(" a b , c ") == "a b, c"


@pytest.mark.parametrize(
    ("instances", "error"),
    [
        ([], "at least one label"),
        (["py", "py "], "twice"),
        (["py, 3.12", "py,3.12"], "twice"),
        ([""], "empty value"),
        (["py,"], "empty value"),
        ([3.12], "valid string"),  # an unquoted YAML number: quote it
    ],
)
def test_bad_declarations_are_load_errors(instances, error) -> None:
    with pytest.raises(ValueError, match=error):
        load_with(instances)
