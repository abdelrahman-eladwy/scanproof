"""Regressions for #50: paths that produced a false VERIFIED (audit for #44).

Each test states the invariant it protects. They use the pure engine, so they fail on the
decision itself rather than on any connector behavior.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from scanproof.evidence.models import ScanScope
from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.engine import Decision, Outcome, RequirementInput, evaluate
from scanproof.policy.models import Policy, PolicyError, load_policy, normalize_scan_path
from scanproof.scanners import get_adapter
from tests.conftest import FIXTURES

NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)
SHA = "a" * 40
BASE = {"tool": "semgrep", "report_path": "semgrep.json"}


def policy(requirements: list[dict], **enforcement: str) -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": "1"},
            "requirements": requirements,
            "enforcement": enforcement,
        }
    )


def pipeline(ref: str | None) -> Pipeline:
    return Pipeline(id=50, sha=SHA, ref=ref, status="success")


def job(name: str) -> InspectedJob:
    latest = Job(id=9, name=name, status=JobStatus.SUCCESS, commit_sha=SHA, finished_at=NOW)
    return InspectedJob(
        name=name, stage=None, latest=latest, attempt_ids=[9], commit_matches_pipeline=True
    )


def clean_report(scanned: list[str] | None = None):
    ev = get_adapter("semgrep").parse((FIXTURES / "semgrep/semgrep-clean.json").read_bytes())
    if scanned is not None:
        ev = ev.model_copy(
            update={"scope": ScanScope(files_scanned=len(scanned), scanned_paths=scanned)}
        )
    return ev


# ------------------------------------------------- P0-1: unknown ref and applies_to

SCOPED = [
    {**BASE, "id": "SAST", "job_name": "sast"},
    {**BASE, "id": "RELEASE_SCAN", "job_name": "release-scan", "applies_to": {"refs": ["main"]}},
]
# The release-only scan job is absent: on main this must block.
SCOPED_INPUTS = {"SAST": RequirementInput(job=job("sast"), evidence=clean_report())}


def test_scoped_requirement_blocks_on_known_ref() -> None:
    assert evaluate(policy(SCOPED), pipeline("main"), SCOPED_INPUTS, now=NOW).decision is (
        Decision.BLOCKED
    )


@pytest.mark.parametrize("ref", [None, "", "   "])
def test_unknown_ref_never_drops_a_scoped_requirement(ref: str | None) -> None:
    """Unknown is never pass: a ref the provider did not report cannot prove 'out of scope'."""
    result = evaluate(policy(SCOPED), pipeline(ref), SCOPED_INPUTS, now=NOW)
    assert result.decision is Decision.INDETERMINATE
    scoped = next(r for r in result.requirements if r.id == "RELEASE_SCAN")
    assert scoped.outcome is Outcome.UNKNOWN
    assert scoped.checks[0].code == "REF_UNKNOWN"


def test_unknown_ref_is_not_nothing_applicable_even_with_allow() -> None:
    """on_nothing_applicable: allow covers refs known to be out of scope, not unknown refs."""
    only_scoped = [SCOPED[1]]
    result = evaluate(
        policy(only_scoped, on_nothing_applicable="allow"), pipeline(None), {}, now=NOW
    )
    assert result.decision is Decision.INDETERMINATE
    known = evaluate(
        policy(only_scoped, on_nothing_applicable="allow"), pipeline("feature/x"), {}, now=NOW
    )
    assert known.decision is Decision.VERIFIED  # unchanged explicit opt-in


def test_wildcard_scope_still_applies_when_ref_unknown() -> None:
    """A pattern that matches every ref does not depend on the ref, so it is evaluated."""
    reqs = [{**BASE, "id": "SAST", "job_name": "sast", "applies_to": {"refs": ["*"]}}]
    result = evaluate(policy(reqs), pipeline(None), SCOPED_INPUTS, now=NOW)
    assert result.decision is Decision.VERIFIED


# ------------------------------------------------- P0-2..4: required_paths semantics


def decide(required: list[str], scanned: list[str]) -> Decision:
    reqs = [{**BASE, "id": "SAST", "job_name": "sast", "checks": {"required_paths": required}}]
    inputs = {"SAST": RequirementInput(job=job("sast"), evidence=clean_report(scanned))}
    return evaluate(policy(reqs), pipeline("main"), inputs, now=NOW).decision


@pytest.mark.parametrize(
    ("required", "scanned"),
    [
        ("src/main/java", "src/main/javascript/app.js"),  # sibling sharing a string prefix
        ("package-lock.json", "package-lock.json.orig"),  # decoy next to the real lockfile
        ("services/payments", "services/payments-mock/handler.py"),
        ("src/", "src/../vendor/lib.py"),  # path escapes the required directory
        ("src", "../src/app.py"),  # path escapes the scan root
    ],
)
def test_required_path_needs_a_segment_boundary(required: str, scanned: str) -> None:
    assert decide([required], [scanned]) is Decision.BLOCKED


@pytest.mark.parametrize(
    ("required", "scanned"),
    [
        ("src/main/java", "src/main/java/App.java"),
        ("src/main/java/", "src/main/java/App.java"),
        ("./src", "src/a.py"),
        ("src", "./src/a.py"),
        ("package-lock.json", "package-lock.json"),
        ("frontend", "frontend/"),
        ("src\\app", "src/app/main.py"),
        ("src/app", "src\\app\\main.py"),
        ("src/./app", "src/app/main.py"),
    ],
)
def test_required_path_still_matches_files_under_it(required: str, scanned: str) -> None:
    assert decide([required], [scanned]) is Decision.VERIFIED


def write_policy(tmp_path, required: list[str]):
    path = tmp_path / "policy.yaml"
    # JSON strings are valid YAML double-quoted scalars, so backslashes arrive exactly as given.
    path.write_text(
        "apiVersion: scanproof.dev/v1alpha1\n"
        "kind: PipelineAssurancePolicy\n"
        "project: {provider: gitlab, id: '1'}\n"
        "requirements:\n"
        "  - {id: SAST, tool: semgrep, job_name: sast, report_path: s.json,\n"
        f"     checks: {{required_paths: {json.dumps(required)}}}}}\n",
        encoding="utf-8",
    )
    return path


def assert_rejected(required: list[str], tmp_path) -> None:
    reqs = [{**BASE, "id": "SAST", "job_name": "sast", "checks": {"required_paths": required}}]
    with pytest.raises(ValueError, match="required_paths"):
        policy(reqs)
    with pytest.raises(PolicyError, match="required_paths"):
        load_policy(write_policy(tmp_path, required))


@pytest.mark.parametrize(
    "required",
    [[""], ["./"], ["."], ["  "], ["src/", ""], ["../src"], ["src/../.."], []],
)
def test_required_paths_that_match_everything_or_nothing_are_load_errors(
    required: list[str], tmp_path
) -> None:
    """A control that cannot fail (or silently does nothing) must be a load error, exit 3."""
    assert_rejected(required, tmp_path)


# ------------------------------------------------- absolute paths are not repository paths

POSIX_ROOTED = ["/repo/src", "/", "/src"]
DRIVE_ROOTED = ["C:\\repo\\src", "C:/repo/src", "c:\\", "D:repo\\src"]  # incl. drive-relative
UNC = ["\\\\server\\share\\src", "//server/share/src", "\\\\?\\C:\\repo\\src"]
ABSOLUTE = POSIX_ROOTED + DRIVE_ROOTED + UNC


@pytest.mark.parametrize("path", ABSOLUTE)
def test_absolute_paths_do_not_normalize(path: str) -> None:
    assert normalize_scan_path(path) is None


@pytest.mark.parametrize("path", ABSOLUTE)
def test_absolute_required_path_is_a_load_error(path: str, tmp_path) -> None:
    """required_paths are repository-relative; an absolute one is exit 3, not a silent match."""
    assert_rejected([path], tmp_path)
    assert_rejected(["src/", path], tmp_path)


@pytest.mark.parametrize(
    ("required", "scanned"),
    [
        ("/repo/src", "/repo/src/app.py"),
        ("C:\\repo\\src", "C:\\repo\\src\\app.py"),
        ("C:/repo/src", "c:/repo/src/app.py"),
        ("\\\\server\\share\\src", "\\\\server\\share\\src\\app.py"),
        ("//server/share/src", "//server/share/src/app.py"),
    ],
)
def test_absolute_requirement_never_matches_absolute_evidence(required: str, scanned: str) -> None:
    """Defense in depth: even a policy object that skipped validation cannot match."""
    valid = policy(
        [{**BASE, "id": "SAST", "job_name": "sast", "checks": {"required_paths": ["src"]}}]
    )
    req = valid.requirements[0]
    bypassed = req.model_copy(
        update={"checks": req.checks.model_copy(update={"required_paths": [required]})}
    )
    unchecked = valid.model_copy(update={"requirements": [bypassed]})
    inputs = {"SAST": RequirementInput(job=job("sast"), evidence=clean_report([scanned]))}
    result = evaluate(unchecked, pipeline("main"), inputs, now=NOW)
    assert result.decision is Decision.BLOCKED
    assert result.requirements[0].checks[-1].code == "REQUIRED_PATH_NOT_SCANNED"


@pytest.mark.parametrize(
    "scanned",
    [
        "/repo/src/app.py",
        "/src/app.py",
        "C:\\repo\\src\\app.py",
        "C:src\\app.py",
        "\\\\server\\share\\src\\app.py",
        "//server/share/src/app.py",
    ],
)
def test_absolute_scanned_paths_never_satisfy_a_relative_requirement(scanned: str) -> None:
    assert decide(["src"], [scanned]) is Decision.BLOCKED


def test_absolute_scanned_paths_are_ignored_not_fatal() -> None:
    """A report mixing absolute and relative paths is judged on its relative ones."""
    absolute = ["/repo/src/a.py", "C:\\repo\\src\\a.py", "\\\\srv\\share\\src\\a.py"]
    assert decide(["src"], absolute) is Decision.BLOCKED
    assert decide(["src"], [*absolute, "src/a.py"]) is Decision.VERIFIED
