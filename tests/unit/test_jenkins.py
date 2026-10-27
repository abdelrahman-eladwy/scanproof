"""Jenkins connector against the real responses of the contract Jenkins (tests/fixtures/
jenkins-real/), mirroring the live self-verify run in platforms-contract.yml."""

from __future__ import annotations

import base64
import re

import pytest

from scanproof.connectors.base import AuthError, ConnectorError
from scanproof.connectors.jenkins import JenkinsConnector, _job_path, _swallowed_failure
from scanproof.policy.engine import Decision
from scanproof.policy.models import load_policy
from scanproof.verification import verify_pipeline
from tests.conftest import FIXTURES

BASE = "https://jenkins.example.com"
J = FIXTURES / "jenkins-real"
POLICIES = FIXTURES.parent / "contract/policies/jenkins"
REPORT = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()


def serve(router, job: str, *, tree: bool = True, steps: int | None = None) -> None:
    d = J / job
    base = f"{BASE}/job/{job}/1"
    router.get(url__regex=rf"^{re.escape(base)}/api/json.*").respond(
        content=(d / "build.json").read_bytes()
    )
    if tree:
        router.get(f"{base}/stages/tree").respond(content=(d / "stages_tree.json").read_bytes())
    else:
        router.get(f"{base}/stages/tree").respond(404)
    if steps is not None:
        router.get(f"{base}/stages/allSteps").respond(steps)
    elif tree:
        router.get(f"{base}/stages/allSteps").respond(
            content=(d / "stages_allSteps.json").read_bytes()
        )
    else:
        router.get(f"{base}/stages/allSteps").respond(404)
    router.get(f"{base}/wfapi/describe").respond(content=(d / "wfapi.json").read_bytes())
    for f in d.glob("stage-*.json"):
        node = f.stem.split("-", 1)[1]
        router.get(f"{base}/execution/node/{node}/wfapi/describe").respond(content=f.read_bytes())
    router.get(url__regex=rf"^{re.escape(base)}/artifact/.*").respond(content=REPORT)


@pytest.fixture
def jenkins(sleeps):
    with JenkinsConnector(BASE, "api-token", username="scanproof", sleep=sleeps.append) as c:
        yield c


EXPECTED = {
    p.stem: int(re.search(r"Expected exit: (\d)", p.read_text())[1])
    for p in POLICIES.glob("*.yaml")
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_live_contract_decisions(jenkins, mock_api, name) -> None:
    policy = load_policy(POLICIES / f"{name}.yaml")
    serve(mock_api, policy.project.id)
    report = verify_pipeline(
        jenkins, policy, instance_url=BASE, project=policy.project.id, pipeline_id=1
    )
    assert report.exit_code == EXPECTED[name], [
        c.message for r in report.requirements for c in r.checks
    ]


def test_matrix_instances_are_named_by_hierarchy(jenkins, mock_api) -> None:
    serve(mock_api, "sast-matrix")
    names = {j.name: j.status.value for j in jenkins.list_jobs("sast-matrix", 1)}
    assert names["Scan / Matrix - LANG = 'go' / sast"] == "failed"
    assert names["Scan / Matrix - LANG = 'python' / sast"] == "success"


def test_without_graph_plugin_falls_back_to_stage_view(jenkins, mock_api) -> None:
    serve(mock_api, "sast-trycatch", tree=False)
    (job,) = jenkins.list_jobs("sast-trycatch", 1)
    assert job.name == "Scan"
    assert job.allow_failure and "caught" in job.raw_status  # wfapi stage nodes show it too


def test_unreadable_step_nodes_make_masking_unknown(jenkins, mock_api) -> None:
    serve(mock_api, "sast-ok", steps=403)
    policy = load_policy(POLICIES / "sast-ok.yaml")
    report = verify_pipeline(jenkins, policy, instance_url=BASE, project="sast-ok", pipeline_id=1)
    assert report.decision is Decision.INDETERMINATE


def test_retry_is_not_a_mask_but_a_swallowed_failure_is() -> None:
    retried = [("sh a", "failure"), ("sh a", "success"), ("archive", "success")]
    swallowed = [("sh a", "failure"), ("echo ignored", "success"), ("archive", "success")]
    assert _swallowed_failure(retried) is None
    assert _swallowed_failure(swallowed) == "sh a"


def test_basic_auth_only_to_the_jenkins_origin(jenkins, mock_api) -> None:
    serve(mock_api, "sast-ok")
    mock_api.get(url__regex=r"^https://jenkins\.example\.com/job/sast-ok/1/artifact/.*").respond(
        302, headers={"Location": "https://storage.example.net/semgrep.json"}
    )
    mock_api.get("https://storage.example.net/semgrep.json").respond(content=REPORT)
    policy = load_policy(POLICIES / "sast-ok.yaml")
    verify_pipeline(jenkins, policy, instance_url=BASE, project="sast-ok", pipeline_id=1)
    expected = "Basic " + base64.b64encode(b"scanproof:api-token").decode()
    for call in mock_api.calls:
        header = call.request.headers.get("authorization")
        if call.request.url.host == "jenkins.example.com":
            assert header == expected
        else:
            assert header is None


def test_token_needs_a_username() -> None:
    with pytest.raises(AuthError, match="JENKINS_USER"):
        JenkinsConnector(BASE, "api-token")


def test_secrets_stay_out_of_repr() -> None:
    with JenkinsConnector(BASE, "api-token", username="scanproof") as c:
        assert "api-token" not in repr(c) and "scanproof:" not in repr(c)


@pytest.mark.parametrize("bad", ["", "a/../b", "a/./b", "a\x00b"])
def test_job_path_rejects_traversal(bad) -> None:
    with pytest.raises(ConnectorError):
        _job_path(bad)


def test_report_path_traversal_and_unarchived_files(jenkins, mock_api) -> None:
    serve(mock_api, "sast-ok")
    job = jenkins.list_jobs("sast-ok", 1)[0]
    with pytest.raises(ConnectorError, match=r"\.\."):
        jenkins.fetch_report("sast-ok", job, "../secrets.txt")
    with pytest.raises(ConnectorError, match="not archived"):
        jenkins.fetch_report("sast-ok", job, "other.json")


def test_commit_from_git_build_data() -> None:
    from scanproof.connectors.jenkins import _branch, _commit

    build = {
        "actions": [
            {},
            {
                "_class": "hudson.plugins.git.util.BuildData",
                "lastBuiltRevision": {
                    "SHA1": "a" * 40,
                    "branch": [{"name": "refs/remotes/origin/main"}],
                },
            },
        ]
    }
    assert _commit(build) == "a" * 40 and _branch(build) == "main"
    assert (
        _commit({"actions": [{"_class": "BuildData", "lastBuiltRevision": {"SHA1": "nope"}}]})
        is None
    )


def test_garbage_responses_are_invalid_not_crashes(jenkins, mock_api) -> None:
    base = f"{BASE}/job/x/1"
    mock_api.get(url__regex=rf"^{re.escape(base)}/api/json.*").respond(json=[1, 2])
    with pytest.raises(ConnectorError, match="not an object"):
        jenkins.get_pipeline("x", 1)


def test_malformed_stage_graph_is_invalid(jenkins, mock_api) -> None:
    serve(mock_api, "sast-ok")
    mock_api.get(f"{BASE}/job/sast-ok/1/stages/tree").respond(
        json={"data": {"stages": [{"no": "id"}]}}
    )
    with pytest.raises(ConnectorError, match="Unexpected stage graph"):
        jenkins.list_jobs("sast-ok", 1)


def test_unknown_stage_state_is_never_success(jenkins, mock_api) -> None:
    serve(mock_api, "sast-ok")
    tree = {"data": {"stages": [{"id": "6", "name": "Scan", "state": "teleported"}]}}
    mock_api.get(f"{BASE}/job/sast-ok/1/stages/tree").respond(json=tree)
    (job,) = jenkins.list_jobs("sast-ok", 1)
    assert job.status.value == "unknown"


CODES = {  # what each live scenario must report, not just its exit code
    "sast-masked": ("FAILURE_MASKED_BY_ALLOW_FAILURE", "failed, but the build continued"),
    "sast-unstable": ("FAILURE_MASKED_BY_ALLOW_FAILURE", "unstable (warnError / unstable)"),
    "sast-trycatch": ("FAILURE_MASKED_BY_ALLOW_FAILURE", "caught (try/catch)"),
    "sast-parallel": ("FAILURE_MASKED_BY_ALLOW_FAILURE", "failed, but the build continued"),
    "sast-skipped": ("JOB_NOT_SUCCESS", "ended 'skipped'"),
    "sast-failed": ("JOB_NOT_SUCCESS", "ended 'failed'"),
}


@pytest.mark.parametrize("name", sorted(CODES))
def test_live_contract_codes(jenkins, mock_api, name) -> None:
    policy = load_policy(POLICIES / f"{name}.yaml")
    serve(mock_api, policy.project.id)
    report = verify_pipeline(
        jenkins, policy, instance_url=BASE, project=policy.project.id, pipeline_id=1
    )
    (check,) = [c for c in report.requirements[0].checks if c.check == "job_success"]
    code, text = CODES[name]
    assert check.code == code and text in check.message, check.message
