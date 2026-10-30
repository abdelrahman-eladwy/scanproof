"""verify-release: a component whose connector cannot be built is INDETERMINATE on its own (#131).

The CLI used to turn a ConnectorError raised while *building* a connector (e.g. a non-HTTPS
component url) into an immediate exit, so later components were never verified and `-o`
received no release report.
"""

from __future__ import annotations

import json

import respx
from typer.testing import CliRunner

from scanproof.cli import EXIT_INDETERMINATE, EXIT_USAGE, app
from tests.unit.test_release import BACKEND

runner = CliRunner()


def _release(tmp_path, components: str):
    (tmp_path / "gitlab.yaml").write_text(BACKEND)
    path = tmp_path / "release.yaml"
    path.write_text(
        "apiVersion: scanproof.dev/v1alpha1\nkind: ReleaseAssurance\n"
        "metadata: {name: r}\ncomponents:\n" + components
    )
    return path


@respx.mock(assert_all_called=False)
def test_unbuildable_component_does_not_stop_the_release(respx_mock, tmp_path, monkeypatch) -> None:
    respx_mock.route().respond(404)  # the reachable component's pipeline does not exist
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-x")
    path = _release(
        tmp_path,
        "  - {name: insecure, policy: gitlab.yaml, pipeline: 1, url: 'http://gl.example.com'}\n"
        "  - {name: reachable, policy: gitlab.yaml, pipeline: 2, url: 'https://gl.example.com'}\n",
    )
    out = tmp_path / "report.json"
    result = runner.invoke(app, ["verify-release", "-R", str(path), "-o", str(out)])

    assert result.exit_code == EXIT_INDETERMINATE, result.output
    report = json.loads(out.read_text())
    assert report["decision"] == "INDETERMINATE"
    by_name = {c["name"]: c for c in report["components"]}
    assert set(by_name) == {"insecure", "reachable"}
    assert by_name["insecure"]["decision"] == "INDETERMINATE"
    assert "non-HTTPS" in by_name["insecure"]["error"]
    assert by_name["reachable"]["decision"] == "INDETERMINATE"
    assert respx_mock.calls, "the second component must still be checked"


def test_missing_token_is_still_a_usage_error(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    path = _release(tmp_path, "  - {name: a, policy: gitlab.yaml, pipeline: 1}\n")
    result = runner.invoke(app, ["verify-release", "-R", str(path)])
    assert result.exit_code == EXIT_USAGE
    assert "GITLAB_TOKEN" in result.output
