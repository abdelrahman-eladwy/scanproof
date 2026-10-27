"""verify end to end with real signed evidence served through a GitHub API double.

The fixtures are from run 40459499786 of this repository, so the pipeline below is that run;
changing its id or commit is how "attested in another run / at another commit" is reproduced.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("sigstore", reason="needs the attestations extra")

from scanproof.attestation.verify import TrustConfig
from scanproof.connectors.github import GitHubConnector
from scanproof.connectors.gitlab import GitLabConnector
from scanproof.models import Pipeline
from scanproof.policy.engine import Decision
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.conftest import FIXTURES
from tests.fake_github import API, FakeGitHub

A = FIXTURES / "attestations"
RUN = dict(kv.split("=") for kv in (A / "run.txt").read_text().split())
REPO = "abdelrahman-eladwy/scanproof"
REPORT = (A / "semgrep.json").read_bytes()
IMAGE = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
WF = r"https://github\.com/abdelrahman-eladwy/scanproof/\.github/workflows"
SIGNER = {
    "issuer": "https://token.actions.githubusercontent.com",
    "repository": f"https://github.com/{REPO}",
    "workflow": rf"{WF}/attestation-contract\.yml@refs/heads/.+",
}
TRUST = TrustConfig([A / "trusted_root.production.json"])


def api_bundles(name: str) -> list[dict]:
    return [a["bundle"] for a in json.loads((A / name).read_text())["attestations"]]


@pytest.fixture
def gh(mock_api) -> FakeGitHub:
    fake = FakeGitHub(mock_api, repo=REPO, run_id=int(RUN["run_id"]), sha=RUN["sha"])
    fake.job(1, "sast")
    fake.job(2, "container")
    fake.artifact(
        10,
        "semgrep-report",
        {
            "semgrep.json": REPORT,
            "semgrep.json.provenance.sigstore.json": (
                A / "semgrep.provenance.sigstore.json"
            ).read_bytes(),
        },
    )
    fake.artifact(11, "trivy-report", {"trivy.json": (A / "trivy.json").read_bytes()})
    fake.artifact(
        12,
        "reusable-bundle",
        {
            "semgrep.json.reusable.sigstore.json": (
                A / "semgrep.reusable.sigstore.json"
            ).read_bytes()
        },
    )
    fake.attestations[IMAGE.removeprefix("sha256:")] = [
        api_bundles(f"github-attestations-{IMAGE[7:19]}.json")
    ]
    return fake


@pytest.fixture
def conn(sleeps):
    with GitHubConnector(API, "ghp_test", sleep=sleeps.append, max_retries=1) as c:
        yield c


def policy(*requirements) -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "github", "id": REPO},
            "requirements": list(requirements),
        }
    )


def sast(**attestation) -> dict:
    spec = {
        "source": "artifact",
        "bundle_path": "semgrep.json.provenance.sigstore.json",
        "signer": SIGNER,
    } | attestation
    return {
        "id": "SAST",
        "tool": "semgrep",
        "job_name": "sast",
        "artifact_name": "semgrep-report",
        "report_path": "semgrep.json",
        "attestation": spec,
    }


def image(**attestation) -> dict:
    spec = {
        "source": "platform",
        "subject": "image",
        "predicate_type": "https://cosign.sigstore.dev/attestation/vuln/v1",
        "signer": SIGNER,
    } | attestation
    return {
        "id": "IMAGE",
        "tool": "trivy",
        "job_name": "container",
        "artifact_name": "trivy-report",
        "report_path": "trivy.json",
        "checks": {"image_digest_must_match": IMAGE},
        "attestation": spec,
    }


def verify(conn, gh, pol):
    gh.install()
    return verify_pipeline(
        conn, pol, instance_url=API, project=REPO, pipeline_id=gh.run_id, trust=TRUST
    )


def codes(report) -> dict[str, str]:
    return {
        f"{r.id}.{c.check}": c.code
        for r in report.requirements
        for c in r.checks
        if c.check == "attestation"
    }


def test_report_and_image_attested_by_this_run(conn, gh) -> None:
    report = verify(conn, gh, policy(sast(), image()))
    assert report.decision is Decision.VERIFIED, codes(report)
    assert codes(report) == {
        "SAST.attestation": "ATTESTATION_VERIFIED",
        "IMAGE.attestation": "ATTESTATION_VERIFIED",
    }
    # the store also holds the same image's attestation from the previous run
    assert "1 of 2 bundles" in report.requirements[1].checks[-1].message
    assert len(report.attestations["IMAGE"]) == 2
    assert [a.run_matches for a in report.attestations["IMAGE"]].count(True) == 1


def test_report_replaced_after_signing(conn, gh) -> None:
    """Someone uploads a different report next to the genuine bundle."""
    gh.artifacts.clear()
    gh.blobs.clear()
    gh.artifact(
        10,
        "semgrep-report",
        {
            "semgrep.json": REPORT.replace(b'"results"', b'"results" ', 1),
            "semgrep.json.provenance.sigstore.json": (
                A / "semgrep.provenance.sigstore.json"
            ).read_bytes(),
        },
    )
    report = verify(conn, gh, policy(sast()))
    assert report.decision is Decision.BLOCKED
    assert codes(report) == {"SAST.attestation": "ATTESTATION_SUBJECT_MISMATCH"}


def test_evidence_replayed_from_another_run(conn, gh) -> None:
    """Genuine report + genuine bundle, copied into a later run that never scanned."""
    gh.run_id += 1
    for j in gh.jobs:
        j["run_id"] = gh.run_id
    report = verify(conn, gh, policy(sast(same_commit=False)))
    assert report.decision is Decision.BLOCKED
    assert codes(report) == {"SAST.attestation": "ATTESTATION_WRONG_RUN"}


def test_evidence_from_another_commit(conn, gh) -> None:
    gh.sha = "f" * 40
    report = verify(conn, gh, policy(sast(same_run=False)))
    assert codes(report) == {"SAST.attestation": "ATTESTATION_WRONG_COMMIT"}


def test_reusable_workflow_bundle_vs_caller_policy(conn, gh) -> None:
    caller = sast(
        artifact_name="reusable-bundle", bundle_path="semgrep.json.reusable.sigstore.json"
    )
    assert codes(verify(conn, gh, policy(caller))) == {
        "SAST.attestation": "ATTESTATION_SIGNER_MISMATCH"
    }
    reusable = sast(
        artifact_name="reusable-bundle",
        bundle_path="semgrep.json.reusable.sigstore.json",
        signer=SIGNER | {"workflow": rf"{WF}/reusable-attest\.yml@refs/heads/.+"},
    )
    assert verify(conn, gh, policy(reusable)).decision is Decision.VERIFIED


def test_bundle_missing_from_artifact(conn, gh) -> None:
    report = verify(conn, gh, policy(sast(bundle_path="nope.sigstore.json")))
    assert report.decision is Decision.BLOCKED
    assert codes(report) == {"SAST.attestation": "ATTESTATION_MISSING"}


def test_no_attestation_in_the_store(conn, gh) -> None:
    gh.attestations.clear()  # GitHub answers 404
    report = verify(conn, gh, policy(image()))
    assert codes(report) == {"IMAGE.attestation": "ATTESTATION_MISSING"}


def test_store_forbidden_is_unknown_not_missing(conn, gh) -> None:
    gh.attestations[IMAGE[7:]] = 403
    report = verify(conn, gh, policy(image()))
    assert report.decision is Decision.INDETERMINATE
    assert codes(report) == {"IMAGE.attestation": "ATTESTATION_UNAVAILABLE"}


def test_store_pagination_finds_bundle_on_page_two(conn, gh) -> None:
    bundles = api_bundles(f"github-attestations-{IMAGE[7:19]}.json")
    old = [b for b in bundles if RUN["run_id"] not in json.dumps(b)]
    new = [b for b in bundles if RUN["run_id"] in json.dumps(b)]
    gh.attestations[IMAGE[7:]] = [old, new]
    assert verify(conn, gh, policy(image())).decision is Decision.VERIFIED


def test_oversized_store_page_is_unavailable(conn, gh, sleeps) -> None:
    conn.max_artifact_bytes = 1000  # the trivy report download fails too
    report = verify(conn, gh, policy(image(), sast()))
    assert report.decision is Decision.INDETERMINATE
    assert codes(report) == {
        "IMAGE.attestation": "ATTESTATION_UNAVAILABLE",  # looked, store page too large
        "SAST.attestation": "ATTESTATION_NO_SUBJECT",  # no report bytes to bind to
    }


def test_store_pagination_cannot_leave_the_api_origin(conn, gh, mock_api) -> None:
    # registered before gh.install(), so it wins over the fake's own attestations route
    mock_api.get(url__regex=rf"{API}/repos/{REPO}/attestations/sha256:.*").respond(
        200,
        json={"attestations": []},
        headers={"Link": '<https://evil.example/next>; rel="next"'},
    )
    report = verify(conn, gh, policy(image()))
    assert codes(report) == {"IMAGE.attestation": "ATTESTATION_UNAVAILABLE"}


def test_store_request_never_sends_the_token_elsewhere(conn, gh, mock_api) -> None:
    verify(conn, gh, policy(image()))
    for call in mock_api.calls:
        if call.request.url.host != "api.github.com":
            assert "authorization" not in call.request.headers


# ---------------------------------------------------------------- run matching


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("https://github.com/acme/app/actions/runs/7/attempts/2", True),
        ("https://github.com/acme/app/actions/runs/7", True),
        ("https://github.com/ACME/App/actions/runs/7/attempts/1", True),
        ("https://github.com/acme/app/actions/runs/8/attempts/1", False),
        ("https://github.com/evil/app/actions/runs/7/attempts/1", False),
        ("https://ghes.example.com/acme/app/actions/runs/7/attempts/1", False),
        ("https://github.com/acme/app/-/jobs/7", None),
        (None, None),
    ],
)
def test_github_run_matches(uri, expected) -> None:
    pipe = Pipeline(
        id=7, sha="a", status="success", web_url="https://github.com/acme/app/actions/runs/7"
    )
    with GitHubConnector(API, "t") as c:
        assert c.run_matches(uri, pipe, set()) is expected


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("https://gitlab.example.com/group/app/-/jobs/101", True),
        ("https://gitlab.example.com/group/sub/app/-/jobs/102", True),  # child-pipeline job
        ("https://gitlab.example.com/group/app/-/jobs/999", False),
        ("https://gitlab.com/group/app/-/jobs/101", False),
        ("https://gitlab.example.com/group/app/actions/runs/101", None),
        (None, None),
    ],
)
def test_gitlab_run_matches(uri, expected) -> None:
    with GitLabConnector("https://gitlab.example.com", "t") as c:
        assert c.run_matches(uri, Pipeline(id=5, sha="a", status="success"), {101, 102}) is expected


def test_gitlab_has_no_store() -> None:
    from scanproof.connectors.base import ConnectorError, ErrorKind

    with (
        GitLabConnector("https://gitlab.example.com", "t") as c,
        pytest.raises(ConnectorError) as e,
    ):
        c.fetch_attestations("1", "sha256:" + "a" * 64)
    assert e.value.kind is ErrorKind.UNSUPPORTED


def test_bad_digest_never_reaches_the_api() -> None:
    from scanproof.connectors.base import ConnectorError

    with GitHubConnector(API, "t") as c, pytest.raises(ConnectorError, match="not a sha256"):
        c.fetch_attestations("acme/app", "sha256:../../evil")
