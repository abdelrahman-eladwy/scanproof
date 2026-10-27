"""verify-release: one decision over several pipelines on different platforms."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from scanproof.cli import app
from scanproof.connectors.github import GitHubConnector
from scanproof.connectors.gitlab import GitLabConnector
from scanproof.policy.engine import Decision
from scanproof.policy.models import PolicyError
from scanproof.release import load_release, verify_release
from tests.conftest import BASE, FIXTURES
from tests.fake_github import API as GH_API
from tests.fake_github import EXIT1, FakeGitHub
from tests.fake_gitlab import FakeGitLab

SEMGREP = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()

BACKEND = """
apiVersion: scanproof.dev/v1alpha1
kind: PipelineAssurancePolicy
project: {provider: gitlab, id: "123"}
requirements:
  - {id: SAST, tool: semgrep, job_name: semgrep-sast, report_path: semgrep.json}
"""
FRONTEND = """
apiVersion: scanproof.dev/v1alpha1
kind: PipelineAssurancePolicy
project: {provider: github, id: acme/app}
requirements:
  - {id: SAST, tool: semgrep, job_name: sast, artifact_name: scan-report, report_path: semgrep.json}
"""


def write_release(tmp_path, components: str) -> object:
    (tmp_path / "policies").mkdir(exist_ok=True)
    (tmp_path / "policies/backend.yaml").write_text(BACKEND)
    (tmp_path / "policies/frontend.yaml").write_text(FRONTEND)
    path = tmp_path / "release.yaml"
    path.write_text(
        "apiVersion: scanproof.dev/v1alpha1\nkind: ReleaseAssurance\n"
        "metadata: {name: shop-2.3}\ncomponents:\n" + components
    )
    return path


COMPONENTS = """  - {name: backend, policy: policies/backend.yaml, pipeline: 1042}
  - {name: frontend, policy: policies/frontend.yaml, pipeline: 77}
"""


@pytest.fixture
def platforms(mock_api):
    gl = FakeGitLab(mock_api)
    gl.job(1, "semgrep-sast", files={"semgrep.json": SEMGREP})
    gh = FakeGitHub(mock_api)
    gh.job(1, "sast")
    gh.artifact(10, "scan-report", {"semgrep.json": SEMGREP})
    return gl, gh


def connect(sleeps):
    def make(provider, url):
        if provider == "gitlab":
            return GitLabConnector(BASE, "glpat-x", sleep=sleeps.append, max_retries=0)
        return GitHubConnector(GH_API, "ghp-x", sleep=sleeps.append, max_retries=0)

    return make


def test_every_component_verified(tmp_path, platforms, sleeps) -> None:
    gl, gh = platforms
    gl.install()
    gh.install()
    path = write_release(tmp_path, COMPONENTS)
    report = verify_release(load_release(path), path.parent, connect(sleeps))
    assert report.decision is Decision.VERIFIED and report.exit_code == 0
    assert [(c.name, c.provider) for c in report.components] == [
        ("backend", "gitlab"),
        ("frontend", "github"),
    ]


def test_one_blocked_component_blocks_the_release(tmp_path, platforms, sleeps) -> None:
    gl, gh = platforms
    gh.annotations[1] = [[EXIT1]]  # frontend scan step failed under continue-on-error
    gl.install()
    gh.install()
    path = write_release(tmp_path, COMPONENTS)
    report = verify_release(load_release(path), path.parent, connect(sleeps))
    assert report.decision is Decision.BLOCKED and report.exit_code == 1
    assert {c.name: c.decision for c in report.components} == {
        "backend": Decision.VERIFIED,
        "frontend": Decision.BLOCKED,
    }


def test_unreachable_component_is_indeterminate(tmp_path, platforms, sleeps) -> None:
    gl, gh = platforms
    gl.pipeline_status = 403
    gl.install()
    gh.install()
    path = write_release(tmp_path, COMPONENTS)
    report = verify_release(load_release(path), path.parent, connect(sleeps))
    assert report.decision is Decision.INDETERMINATE
    assert report.components[0].error.startswith("AUTH")


def test_pipeline_id_from_env(tmp_path, platforms, sleeps, monkeypatch) -> None:
    gl, gh = platforms
    gl.install()
    gh.install()
    monkeypatch.setenv("FRONTEND_RUN", "77")
    path = write_release(
        tmp_path,
        "  - {name: frontend, policy: policies/frontend.yaml, pipeline: '${FRONTEND_RUN}'}\n",
    )
    report = verify_release(load_release(path), path.parent, connect(sleeps))
    assert report.components[0].pipeline == 77 and report.decision is Decision.VERIFIED


@pytest.mark.parametrize(
    ("components", "message"),
    [
        (
            "  - {name: a, policy: policies/backend.yaml, pipeline: 1}\n"
            "  - {name: a, policy: policies/frontend.yaml, pipeline: 2}\n",
            "unique",
        ),
        ("  - {name: a, policy: policies/backend.yaml, pipeline: '${NOT_SET_X}'}\n", "not set"),
        ("  - {name: a, policy: policies/backend.yaml, pipeline: 1, extra: 1}\n", "unknown field"),
        ("", "components"),
    ],
)
def test_invalid_release_files(tmp_path, components, message) -> None:
    with pytest.raises(PolicyError, match=message):
        load_release(write_release(tmp_path, components))


def test_missing_policy_is_a_usage_error(tmp_path, sleeps) -> None:
    path = write_release(tmp_path, "  - {name: a, policy: policies/nope.yaml, pipeline: 1}\n")
    with pytest.raises(PolicyError, match="cannot read policy"):
        verify_release(load_release(path), path.parent, connect(sleeps))


def test_cli_end_to_end(tmp_path, platforms, monkeypatch) -> None:
    gl, gh = platforms
    gl.install()
    gh.install()
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-x")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-x")
    path = write_release(tmp_path, COMPONENTS)
    out = tmp_path / "report.json"
    result = CliRunner().invoke(
        app,
        [
            "verify-release",
            "-R",
            str(path),
            "--gitlab-url",
            BASE,
            "--github-url",
            GH_API,
            "-o",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["decision"] == "VERIFIED"
    assert "Release decision: VERIFIED" in result.output
