"""How the CLI turns options and environment into a connector, for every provider.

Pins URL defaults and overrides, token/username lookup, anonymous mode and usage errors, so
refactoring the CLI's connector setup cannot silently change which host or credential is used.
Each connector class is replaced by a recorder that captures its arguments and then fails, so
no network is touched and the command exits INDETERMINATE.
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from scanproof import cli
from scanproof.cli import EXIT_INDETERMINATE, EXIT_USAGE, app
from scanproof.connectors.base import ConnectorError, ErrorKind

runner = CliRunner()
ENV_VARS = [
    "GITLAB_TOKEN",
    "GITHUB_TOKEN",
    "AZURE_DEVOPS_TOKEN",
    "JENKINS_TOKEN",
    "BITBUCKET_TOKEN",
    "JENKINS_USER",
    "BITBUCKET_USER",
    "AZURE_DEVOPS_URL",
    "JENKINS_URL",
    "BITBUCKET_API_URL",
    "GITLAB_URL",
    "GITHUB_API_URL",
    "MY_TOKEN",
    "MY_USER",
]
CLASSES = {
    "gitlab": "GitLabConnector",
    "github": "GitHubConnector",
    "azure-devops": "AzureDevOpsConnector",
    "jenkins": "JenkinsConnector",
    "bitbucket": "BitbucketConnector",
}


class _Unreachable:
    """A connector that was built fine but cannot reach its platform."""

    def __init__(self, provider: str, base_url: str) -> None:
        self.provider, self.base_url = provider, base_url

    def __enter__(self) -> _Unreachable:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def __getattr__(self, name: str):
        raise ConnectorError(ErrorKind.NETWORK, "recorded")


def _recorders(monkeypatch, *, fail_on_build: bool) -> list[tuple[str, tuple, dict[str, Any]]]:
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    calls: list[tuple[str, tuple, dict[str, Any]]] = []
    for provider, cls in CLASSES.items():

        def record(*args, _provider=provider, **kwargs):
            calls.append((_provider, args, kwargs))
            if fail_on_build:
                raise ConnectorError(ErrorKind.NETWORK, "recorded")
            return _Unreachable(_provider, args[0])

        monkeypatch.setattr(cli, cls, record)
    return calls


@pytest.fixture
def built(monkeypatch) -> list[tuple[str, tuple, dict[str, Any]]]:
    """Connector classes replaced by recorders that fail while connecting."""
    return _recorders(monkeypatch, fail_on_build=True)


@pytest.fixture
def opened(monkeypatch) -> list[tuple[str, tuple, dict[str, Any]]]:
    """Connector classes replaced by recorders that build, then fail on first use."""
    return _recorders(monkeypatch, fail_on_build=False)


def _inspect(*extra: str):
    return runner.invoke(app, ["inspect", "-p", "acme/app", "--pipeline", "7", *extra])


@pytest.mark.parametrize(
    ("provider", "env", "url", "token"),
    [
        ("gitlab", {"GITLAB_TOKEN": "gl"}, "https://gitlab.com", "gl"),
        ("github", {"GITHUB_TOKEN": "gh"}, "https://api.github.com", "gh"),
        ("azure-devops", {"AZURE_DEVOPS_TOKEN": "az"}, "https://dev.azure.com", "az"),
        ("bitbucket", {"BITBUCKET_TOKEN": "bb"}, "https://api.bitbucket.org/2.0", "bb"),
    ],
)
def test_default_url_and_token_per_provider(built, monkeypatch, provider, env, url, token):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    result = _inspect("--provider", provider)
    assert result.exit_code == EXIT_INDETERMINATE, result.output
    [(name, args, kwargs)] = built
    assert (name, args[0], args[1]) == (provider, url, token)
    assert kwargs["anonymous"] is False
    assert kwargs["ca_bundle"] is None


def test_provider_name_is_case_insensitive_and_defaults_to_gitlab(built, monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "gl")
    assert _inspect().exit_code == EXIT_INDETERMINATE
    assert _inspect("--provider", "GitLab").exit_code == EXIT_INDETERMINATE
    assert [c[0] for c in built] == ["gitlab", "gitlab"]


def test_gitlab_and_github_urls_come_from_their_own_options(built, monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "gl")
    monkeypatch.setenv("GITHUB_TOKEN", "gh")
    _inspect("--gitlab-url", "https://gl.example.com", "--url", "https://ignored.example.com")
    _inspect("--provider", "github", "--github-url", "https://ghe.example.com/api/v3")
    assert [c[1][0] for c in built] == ["https://gl.example.com", "https://ghe.example.com/api/v3"]


def test_url_option_beats_env_beats_default(built, monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_TOKEN", "az")
    monkeypatch.setenv("AZURE_DEVOPS_URL", "https://env.example.com")
    _inspect("--provider", "azure-devops")
    _inspect("--provider", "azure-devops", "--url", "https://opt.example.com")
    assert [c[1][0] for c in built] == ["https://env.example.com", "https://opt.example.com"]


def test_jenkins_needs_a_url(built, monkeypatch):
    monkeypatch.setenv("JENKINS_TOKEN", "jk")
    result = _inspect("--provider", "jenkins")
    assert result.exit_code == EXIT_USAGE
    assert "JENKINS_URL" in result.output
    assert built == []


def test_jenkins_and_bitbucket_read_username_from_env(built, monkeypatch):
    monkeypatch.setenv("JENKINS_TOKEN", "jk")
    monkeypatch.setenv("JENKINS_USER", "alice")
    monkeypatch.setenv("BITBUCKET_TOKEN", "bb")
    monkeypatch.setenv("MY_USER", "bob")
    _inspect("--provider", "jenkins", "--url", "https://ci.example.com")
    _inspect("--provider", "bitbucket", "--user-env", "MY_USER")
    assert [c[2]["username"] for c in built] == ["alice", "bob"]


def test_unset_username_is_none_not_empty(built, monkeypatch):
    monkeypatch.setenv("JENKINS_TOKEN", "jk")
    monkeypatch.setenv("JENKINS_USER", "")
    _inspect("--provider", "jenkins", "--url", "https://ci.example.com")
    assert built[0][2]["username"] is None


def test_token_env_override(built, monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "custom")
    _inspect("--token-env", "MY_TOKEN")
    assert built[0][1][1] == "custom"


def test_missing_token_is_usage_error(built):
    result = _inspect("--provider", "github")
    assert result.exit_code == EXIT_USAGE
    assert "GITHUB_TOKEN" in result.output
    assert built == []


def test_anonymous_never_sends_a_token_even_if_set(built, monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "must-not-be-used")
    _inspect("--anonymous")
    [(_, args, kwargs)] = built
    assert args[1] is None
    assert kwargs["anonymous"] is True


def test_auth_scheme_reaches_azure_only_and_is_validated(built, monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_TOKEN", "az")
    _inspect("--provider", "azure-devops", "--auth-scheme", "bearer")
    assert built[0][2]["auth_scheme"] == "bearer"
    result = _inspect("--provider", "azure-devops", "--auth-scheme", "ntlm")
    assert result.exit_code == EXIT_USAGE
    assert len(built) == 1


def test_unknown_provider_is_usage_error(built):
    result = _inspect("--provider", "circleci")
    assert result.exit_code == EXIT_USAGE
    assert built == []


def test_ca_bundle_is_passed_as_a_string(built, monkeypatch, tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("x")
    monkeypatch.setenv("GITLAB_TOKEN", "gl")
    _inspect("--ca-bundle", str(bundle))
    assert built[0][2]["ca_bundle"] == str(bundle)


def test_connector_error_while_connecting_is_indeterminate(built, monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "gl")
    result = _inspect()
    assert result.exit_code == EXIT_INDETERMINATE
    assert "INDETERMINATE: NETWORK: recorded" in result.output


JENKINS_POLICY = """
apiVersion: scanproof.dev/v1alpha1
kind: PipelineAssurancePolicy
project: {provider: jenkins, id: app}
requirements:
  - {id: SAST, tool: semgrep, job_name: sast, report_path: semgrep.json}
"""


def test_verify_release_routes_component_urls_to_the_right_option(opened, monkeypatch, tmp_path):
    """A component's `url:` replaces the GitLab/GitHub URL for its own provider, or is the
    --url of any other provider. Components without one use the command-line defaults."""
    from tests.unit.test_release import BACKEND, FRONTEND

    for var, value in {"GITLAB_TOKEN": "gl", "GITHUB_TOKEN": "gh", "JENKINS_TOKEN": "jk"}.items():
        monkeypatch.setenv(var, value)
    (tmp_path / "gitlab.yaml").write_text(BACKEND)
    (tmp_path / "github.yaml").write_text(FRONTEND)
    (tmp_path / "jenkins.yaml").write_text(JENKINS_POLICY)
    release = tmp_path / "release.yaml"
    release.write_text(
        "apiVersion: scanproof.dev/v1alpha1\nkind: ReleaseAssurance\n"
        "metadata: {name: r}\ncomponents:\n"
        "  - {name: a, policy: gitlab.yaml, pipeline: 1}\n"
        "  - {name: b, policy: gitlab.yaml, pipeline: 2, url: 'https://gl2.example.com'}\n"
        "  - {name: c, policy: github.yaml, pipeline: 3, url: 'https://ghe.example.com/api/v3'}\n"
        "  - {name: d, policy: jenkins.yaml, pipeline: 4, url: 'https://ci.example.com'}\n"
    )
    result = runner.invoke(
        app, ["verify-release", "-R", str(release), "--gitlab-url", "https://gl1.example.com"]
    )
    assert result.exit_code == EXIT_INDETERMINATE, result.output
    assert [(c[0], c[1][0]) for c in opened] == [
        ("gitlab", "https://gl1.example.com"),
        ("gitlab", "https://gl2.example.com"),
        ("github", "https://ghe.example.com/api/v3"),
        ("jenkins", "https://ci.example.com"),
    ]
