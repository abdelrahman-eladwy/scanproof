from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from scanproof.cli import EXIT_INDETERMINATE, EXIT_OK, EXIT_USAGE, app
from tests.conftest import API, BASE, TOKEN, load_fixture

runner = CliRunner()
ARGS = ["inspect", "--project", "123", "--pipeline", "1042", "--gitlab-url", BASE]


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)


def _mock_ok(mock_api) -> None:
    mock_api.get(f"{API}/projects/123/pipelines/1042").respond(
        json=load_fixture("gitlab/pipeline.json")
    )
    mock_api.get(f"{API}/projects/123/pipelines/1042/jobs").respond(
        json=load_fixture("gitlab/jobs_page1.json")
    )


def test_inspect_prints_json_to_stdout(env, mock_api) -> None:
    _mock_ok(mock_api)
    result = runner.invoke(app, ARGS)

    assert result.exit_code == EXIT_OK, result.output
    data = json.loads(result.stdout)
    assert data["pipeline"]["id"] == 1042
    assert {j["name"] for j in data["jobs"]} == {"semgrep-sast", "trivy-image"}
    assert "pipeline inspection" in result.stderr
    assert TOKEN not in result.stdout + result.stderr


def test_inspect_writes_output_file(env, mock_api, tmp_path) -> None:
    _mock_ok(mock_api)
    out = tmp_path / "inspection.json"
    result = runner.invoke(app, [*ARGS, "--output", str(out), "--quiet"])

    assert result.exit_code == EXIT_OK
    assert result.stdout == ""
    assert json.loads(out.read_text())["project"] == "123"


def test_auth_failure_is_indeterminate(env, mock_api) -> None:
    mock_api.get(f"{API}/projects/123/pipelines/1042").respond(403)
    result = runner.invoke(app, ARGS)

    assert result.exit_code == EXIT_INDETERMINATE
    assert "INDETERMINATE: AUTH" in result.stderr
    assert TOKEN not in result.stderr


def test_network_failure_is_indeterminate(env, mock_api) -> None:
    mock_api.get(f"{API}/projects/123/pipelines/1042").side_effect = httpx.ConnectTimeout("t/o")
    result = runner.invoke(app, ARGS)
    assert result.exit_code == EXIT_INDETERMINATE


def test_missing_token_is_usage_error(monkeypatch) -> None:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    result = runner.invoke(app, ARGS)
    assert result.exit_code == EXIT_USAGE


def test_custom_token_env(monkeypatch, mock_api) -> None:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    monkeypatch.setenv("AUDIT_TOKEN", TOKEN)
    _mock_ok(mock_api)
    result = runner.invoke(app, [*ARGS, "--token-env", "AUDIT_TOKEN"])
    assert result.exit_code == EXIT_OK


@pytest.mark.parametrize(
    "argv",
    [["inspect", "--pipeline", "not-a-number"], ["inspect", "--no-such-flag"]],
)
def test_usage_errors_exit_3_not_2(argv) -> None:
    """Exit 2 means INDETERMINATE; a typo must not be mistaken for it."""
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-c", "from scanproof.cli import run; run()", *argv],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == EXIT_USAGE, proc.stderr


# ---------------------------------------------------------------- evidence command

FX = Path(__file__).parent.parent / "fixtures"


def test_evidence_from_local_file() -> None:
    result = runner.invoke(
        app, ["evidence", "-t", "semgrep", "-f", str(FX / "semgrep/semgrep-findings.json")]
    )
    assert result.exit_code == EXIT_OK
    data = json.loads(result.stdout)
    assert data["parseable"] is True
    assert data["findings"]["total"] == 6
    assert data["source"]["local_file"].endswith("semgrep-findings.json")


def test_evidence_unknown_tool_is_usage_error() -> None:
    result = runner.invoke(
        app, ["evidence", "-t", "fortify", "-f", str(FX / "semgrep/semgrep-clean.json")]
    )
    assert result.exit_code == EXIT_USAGE


def test_evidence_file_and_gitlab_options_are_exclusive() -> None:
    result = runner.invoke(
        app,
        ["evidence", "-t", "semgrep", "-f", str(FX / "semgrep/semgrep-clean.json"), "-p", "123"],
    )
    assert result.exit_code == EXIT_USAGE


def test_evidence_requires_gitlab_options_without_file(env) -> None:
    result = runner.invoke(app, ["evidence", "-t", "semgrep", "-p", "123"])
    assert result.exit_code == EXIT_USAGE
    assert "--pipeline" in result.stderr


EVIDENCE_ARGS = [
    "evidence",
    "-t",
    "semgrep",
    "-p",
    "123",
    "--pipeline",
    "1042",
    "--job",
    "semgrep-sast",
    "--report",
    "semgrep.json",
    "--gitlab-url",
    BASE,
]


def test_evidence_from_gitlab(env, mock_api) -> None:
    _mock_ok(mock_api)
    mock_api.get(f"{API}/projects/123/jobs/8821/artifacts/semgrep.json").respond(
        content=(FX / "semgrep/semgrep-findings.json").read_bytes()
    )
    result = runner.invoke(app, EVIDENCE_ARGS)
    assert result.exit_code == EXIT_OK, result.stderr
    data = json.loads(result.stdout)
    assert data["source"]["job_id"] == 8821
    assert data["findings"]["total"] == 6


def test_evidence_absent_job(env, mock_api) -> None:
    _mock_ok(mock_api)
    args = [*EVIDENCE_ARGS]
    args[args.index("semgrep-sast")] = "no-such-job"
    result = runner.invoke(app, args)
    assert result.exit_code == EXIT_INDETERMINATE
    assert "REQUIRED_JOB_ABSENT" in result.stderr


def test_evidence_missing_report_is_still_evidence(env, mock_api) -> None:
    _mock_ok(mock_api)
    mock_api.get(f"{API}/projects/123/jobs/8821/artifacts/semgrep.json").respond(404)
    result = runner.invoke(app, EVIDENCE_ARGS)
    assert result.exit_code == EXIT_OK
    assert json.loads(result.stdout)["present"] is False


# ---------------------------------------------------------------- verify / validate

POLICY_YAML = """
apiVersion: scanproof.dev/v1alpha1
kind: PipelineAssurancePolicy
metadata: {name: cli-test}
project: {provider: gitlab, id: 123}
requirements:
  - id: SAST-001
    tool: semgrep
    job_name: semgrep-sast
    report_path: semgrep.json
    checks: {scanner_errors_allowed: 0, minimum_scanned_files: 1}
"""


@pytest.fixture
def policy_file(tmp_path):
    p = tmp_path / "scanproof.yaml"
    p.write_text(POLICY_YAML)
    return p


def _verify_args(policy_file):
    return ["verify", "-P", str(policy_file), "--pipeline", "1042", "--gitlab-url", BASE]


def test_verify_verified(env, mock_api, policy_file, tmp_path) -> None:
    _mock_ok(mock_api)
    mock_api.get(f"{API}/projects/123/jobs/8821/artifacts/semgrep.json").respond(
        content=(FX / "semgrep/semgrep-findings.json").read_bytes()
    )
    out = tmp_path / "report.json"
    result = runner.invoke(app, [*_verify_args(policy_file), "-o", str(out)])
    assert result.exit_code == 0, result.stderr
    report = json.loads(out.read_text())
    assert report["decision"] == "VERIFIED"
    assert "Decision: VERIFIED" in result.stderr
    assert TOKEN not in result.stderr + out.read_text()


def test_verify_blocked_exit_1(env, mock_api, policy_file) -> None:
    _mock_ok(mock_api)
    mock_api.get(f"{API}/projects/123/jobs/8821/artifacts/semgrep.json").respond(404)
    result = runner.invoke(app, _verify_args(policy_file))
    assert result.exit_code == 1
    assert json.loads(result.stdout)["decision"] == "BLOCKED"
    assert "REPORT_MISSING" in result.stderr


def test_verify_pipeline_unreachable_writes_indeterminate_report(
    env, mock_api, policy_file, tmp_path
) -> None:
    mock_api.get(f"{API}/projects/123/pipelines/1042").respond(403)
    out = tmp_path / "report.json"
    result = runner.invoke(app, [*_verify_args(policy_file), "-o", str(out)])
    assert result.exit_code == 2
    report = json.loads(out.read_text())
    assert report["decision"] == "INDETERMINATE"
    assert report["error"]["kind"] == "AUTH"


def test_verify_project_override(env, mock_api, policy_file) -> None:
    route = mock_api.get(f"{API}/projects/acme%2Fother/pipelines/1042").respond(404)
    result = runner.invoke(app, [*_verify_args(policy_file), "-p", "acme/other"])
    assert route.called
    assert result.exit_code == 2


def test_verify_invalid_policy_is_usage_error(env, tmp_path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(POLICY_YAML.replace("minimum_scanned_files", "minimum_scaned_files"))
    result = runner.invoke(app, _verify_args(bad))
    assert result.exit_code == EXIT_USAGE
    assert "minimum_scaned_files: unknown field" in result.stderr


def test_validate(policy_file) -> None:
    result = runner.invoke(app, ["validate", "-P", str(policy_file)])
    assert result.exit_code == 0
    assert "OK: policy 'cli-test'" in result.stderr


def test_anonymous_ignores_token_in_env(env, mock_api) -> None:
    """With --anonymous, a GITLAB_TOKEN in the environment must not be sent."""
    _mock_ok(mock_api)
    result = runner.invoke(app, [*ARGS, "--anonymous", "-q"])
    assert result.exit_code == EXIT_OK, result.stderr
    assert all("Authorization" not in c.request.headers for c in mock_api.calls)


def test_missing_token_mentions_anonymous(monkeypatch) -> None:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    result = runner.invoke(app, ARGS)
    assert result.exit_code == EXIT_USAGE
    assert "--anonymous" in result.stderr


def test_verify_provider_must_match_policy(env, policy_file) -> None:
    result = runner.invoke(app, [*_verify_args(policy_file), "--provider", "github"])
    assert result.exit_code == EXIT_USAGE
    assert "contradicts" in result.stderr


def test_unknown_provider(env) -> None:
    result = runner.invoke(app, [*ARGS, "--provider", "jenkins"])
    assert result.exit_code == EXIT_USAGE


def test_github_provider_uses_github_token(monkeypatch, mock_api) -> None:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    route = mock_api.get("https://api.github.com/repos/o/r/actions/runs/7").respond(404)
    result = runner.invoke(app, ["inspect", "--provider", "github", "-p", "o/r", "--pipeline", "7"])
    assert result.exit_code == EXIT_INDETERMINATE
    assert route.calls.last.request.headers["Authorization"] == "Bearer ghp_x"
