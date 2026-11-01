"""Static release gate invariants; live tag/OIDC acceptance remains separate (#183)."""

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"


def test_release_requires_protected_main_ci_and_tag_ancestry() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    jobs = doc["jobs"]
    preflight = jobs["preflight"]
    assert preflight["permissions"] == {"contents": "read", "actions": "read"}
    assert jobs["build"]["needs"] == "preflight"
    assert "git merge-base --is-ancestor" in text
    assert "github.token" in text
    assert '.head_branch == "main"' in text
    assert '.conclusion == "success"' in text
    assert "head_sha=$GITHUB_SHA&event=push&branch=main" in text


def test_untrusted_tests_cannot_request_oidc_token() -> None:
    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    build = jobs["build"]
    assert build["permissions"] == {"contents": "read"}
    assert "id-token" not in build["permissions"]
    assert jobs["attest"]["needs"] == "build"
    assert jobs["attest"]["permissions"]["id-token"] == "write"
    assert jobs["pypi"]["needs"] == "attest"
    assert jobs["image"]["needs"] == "attest"
    assert all(
        "pytest" not in str(step.get("run", ""))
        and "pip install -e" not in str(step.get("run", ""))
        for step in jobs["attest"]["steps"]
    )
