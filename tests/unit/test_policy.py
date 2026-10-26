from __future__ import annotations

from pathlib import Path

import pytest

from scanproof.evidence.models import ScanEvidence, ScanScope, ScanTarget, ScanType
from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.engine import (
    Decision,
    Outcome,
    RequirementInput,
    combine,
    evaluate,
    evaluate_requirement,
)
from scanproof.policy.models import Policy, PolicyError, Requirement, load_policy

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
PIPELINE = Pipeline(id=1, sha=SHA, ref="main", status="success")
EXAMPLE = Path(__file__).parents[2] / "examples/policies/scanproof.yaml"


# ---------------------------------------------------------------- loading


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(text)
    return p


BASE_YAML = """
apiVersion: scanproof.dev/v1alpha1
kind: PipelineAssurancePolicy
project: {provider: gitlab, id: 123}
requirements:
  - {id: SAST-001, tool: semgrep, job_name: s, report_path: s.json%s}
"""


def test_example_policy_loads(monkeypatch) -> None:
    monkeypatch.setenv("RELEASE_IMAGE_DIGEST", DIGEST)
    policy = load_policy(EXAMPLE)
    assert [r.id for r in policy.requirements] == ["SAST-001", "CONTAINER-001"]
    assert policy.requirements[1].checks.image_digest_must_match == DIGEST
    assert policy.project.id == "your-group/scanproof-demo"


def test_numeric_project_id_becomes_string(tmp_path) -> None:
    assert load_policy(write(tmp_path, BASE_YAML % "")).project.id == "123"


def test_defaults_are_strict(tmp_path) -> None:
    checks = load_policy(write(tmp_path, BASE_YAML % "")).requirements[0].checks
    assert checks.job_success and checks.same_commit and checks.report_required
    assert load_policy(write(tmp_path, BASE_YAML % "")).enforcement.on_unknown == "block"


@pytest.mark.parametrize(
    ("snippet", "message"),
    [
        (", checks: {job_sucess: true}", "job_sucess: unknown field"),
        (", colour: red", "colour: unknown field"),
        (", tool: fortify", None),
        (", checks: {scanner_errors_allowed: -1}", "scanner_errors_allowed"),
        (", checks: {image_digest_must_match: 'latest'}", "sha256"),
        (", checks: {image_digest_must_match: '${NOPE_NOT_SET}'}", "NOPE_NOT_SET is not set"),
    ],
)
def test_invalid_policies(tmp_path, snippet, message) -> None:
    text = (BASE_YAML % "").replace("report_path: s.json", "report_path: s.json" + snippet)
    if "tool: fortify" in snippet:
        text = BASE_YAML.replace("tool: semgrep", "tool: fortify") % ""
    with pytest.raises(PolicyError) as exc:
        load_policy(write(tmp_path, text))
    if message:
        assert message in str(exc.value)


def test_duplicate_ids(tmp_path) -> None:
    text = (BASE_YAML % "") + "  - {id: SAST-001, tool: semgrep, job_name: x, report_path: x}\n"
    with pytest.raises(PolicyError, match="duplicate requirement id"):
        load_policy(write(tmp_path, text))


def test_unknown_tool(tmp_path) -> None:
    with pytest.raises(PolicyError, match="unsupported tool 'fortify'"):
        load_policy(write(tmp_path, BASE_YAML.replace("tool: semgrep", "tool: fortify") % ""))


def test_wrong_api_version(tmp_path) -> None:
    with pytest.raises(PolicyError, match="apiVersion"):
        load_policy(write(tmp_path, (BASE_YAML % "").replace("v1alpha1", "v2")))


@pytest.mark.parametrize("text", ["", "- a list", "key: [unclosed"])
def test_not_a_mapping_or_bad_yaml(tmp_path, text) -> None:
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, text))


def test_missing_file(tmp_path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "nope.yaml")


def test_digest_accepts_repo_reference(monkeypatch) -> None:
    monkeypatch.setenv("D", f"registry.example.com/app@{DIGEST}")
    req = Requirement.model_validate(
        {
            "id": "C",
            "tool": "trivy",
            "job_name": "t",
            "report_path": "t.json",
            "checks": {"image_digest_must_match": "${D}"},
        }
    )
    assert req.checks.image_digest_must_match == DIGEST


# ---------------------------------------------------------------- engine edge cases


def requirement(tool="semgrep", **checks) -> Requirement:
    return Requirement.model_validate(
        {"id": "R", "tool": tool, "job_name": "j", "report_path": "r.json", "checks": checks}
    )


def inspected(status="success", sha=SHA, allow_failure=False, raw=None) -> InspectedJob:
    job = Job(
        id=7,
        name="j",
        status=JobStatus(status),
        raw_status=raw or status,
        commit_sha=sha,
        allow_failure=allow_failure,
    )
    return InspectedJob(
        name="j",
        stage="s",
        latest=job,
        attempt_ids=[7],
        commit_matches_pipeline=None if sha is None else sha == SHA,
    )


def evidence(tool="semgrep", **fields) -> ScanEvidence:
    base = {"present": True, "parseable": True, "report_bytes": 10, "scanner_errors": []}
    scan_type = ScanType.SAST if tool == "semgrep" else ScanType.CONTAINER
    return ScanEvidence(tool=tool, scan_type=scan_type, **(base | fields))


def check(req, job=None, ev=None, error=None) -> dict[str, tuple[Outcome, str]]:
    res = evaluate_requirement(
        req, PIPELINE, RequirementInput(job=job, evidence=ev, evidence_error=error)
    )
    return {c.check: (c.outcome, c.code) for c in res.checks}


@pytest.mark.parametrize(
    ("status", "allow_failure", "expected"),
    [
        ("success", False, (Outcome.PASS, "JOB_SUCCEEDED")),
        ("failed", False, (Outcome.FAIL, "JOB_NOT_SUCCESS")),
        ("canceled", True, (Outcome.FAIL, "FAILURE_MASKED_BY_ALLOW_FAILURE")),
        ("skipped", False, (Outcome.FAIL, "JOB_NOT_SUCCESS")),
        ("manual", True, (Outcome.FAIL, "JOB_NOT_SUCCESS")),
        ("pending", False, (Outcome.UNKNOWN, "JOB_NOT_FINISHED")),
        ("unknown", False, (Outcome.UNKNOWN, "JOB_STATUS_UNKNOWN")),
    ],
)
def test_job_status_matrix(status, allow_failure, expected) -> None:
    result = check(requirement(), inspected(status, allow_failure=allow_failure), evidence())
    assert result["job_success"] == expected


def test_commit_unknown() -> None:
    assert check(requirement(), inspected(sha=None), evidence())["same_commit"] == (
        Outcome.UNKNOWN,
        "COMMIT_UNKNOWN",
    )


def test_checks_can_be_disabled() -> None:
    result = check(
        requirement(job_success=False, same_commit=False, report_required=False),
        inspected("failed", sha="f" * 40),
        None,
    )
    assert result == {}


def test_optional_report_absent_is_not_applicable() -> None:
    req = requirement(report_required=False, minimum_scanned_files=1)
    ev = evidence(present=False, parseable=False, parse_error="gone")
    assert check(req, inspected(), ev)["report"] == (
        Outcome.NOT_APPLICABLE,
        "REPORT_OPTIONAL_ABSENT",
    )


def test_wrong_tool_report() -> None:
    assert check(requirement(), inspected(), evidence(tool="trivy"))["report"] == (
        Outcome.FAIL,
        "WRONG_TOOL",
    )


def test_unknowns_never_pass() -> None:
    req = requirement(
        tool="trivy",
        scanner_errors_allowed=0,
        minimum_scanned_files=1,
        required_paths=["src/"],
        image_digest_must_match=DIGEST,
    )
    result = check(req, inspected(), evidence(tool="trivy", scanner_errors=None))
    assert result["scanner_errors"] == (Outcome.UNKNOWN, "SCANNER_ERRORS_UNKNOWN")
    assert result["minimum_scanned_files"] == (Outcome.UNKNOWN, "SCOPE_UNKNOWN")
    assert result["required_paths"] == (Outcome.UNKNOWN, "SCOPE_UNKNOWN")
    assert result["image_digest_must_match"] == (Outcome.UNKNOWN, "IMAGE_DIGEST_UNKNOWN")


def test_scope_and_digest_pass_and_fail() -> None:
    req = requirement(
        tool="trivy",
        minimum_scanned_files=3,
        required_paths=["./src"],
        image_digest_must_match=DIGEST,
    )
    ev = evidence(
        tool="trivy",
        scope=ScanScope(files_scanned=2, scanned_paths=["src/a.py", "lib/b.py"]),
        target=ScanTarget(image_id=DIGEST),
    )
    result = check(req, inspected(), ev)
    assert result["minimum_scanned_files"] == (Outcome.FAIL, "SCOPE_TOO_SMALL")
    assert result["required_paths"] == (Outcome.PASS, "REQUIRED_PATHS_SCANNED")
    assert result["image_digest_must_match"] == (Outcome.PASS, "IMAGE_DIGEST_MATCHES")


def test_combine() -> None:
    assert combine([]) is Outcome.NOT_APPLICABLE
    assert combine([Outcome.PASS, Outcome.NOT_APPLICABLE]) is Outcome.PASS
    assert combine([Outcome.NOT_APPLICABLE] * 2) is Outcome.NOT_APPLICABLE
    assert combine([Outcome.PASS, Outcome.UNKNOWN]) is Outcome.UNKNOWN
    assert combine([Outcome.UNKNOWN, Outcome.FAIL]) is Outcome.FAIL


def test_missing_input_means_job_absent() -> None:
    policy = Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": 1},
            "requirements": [{"id": "R", "tool": "semgrep", "job_name": "j", "report_path": "r"}],
        }
    )
    result = evaluate(policy, PIPELINE, {})
    assert result.decision is Decision.BLOCKED
    assert result.requirements[0].checks[0].code == "REQUIRED_JOB_ABSENT"
    assert policy.name == "unnamed-policy"


def test_exit_codes() -> None:
    assert [d.exit_code for d in Decision] == [0, 1, 2]


def _scoped_policy(refs: list[str]) -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": 1},
            "requirements": [
                {
                    "id": "R",
                    "tool": "semgrep",
                    "job_name": "j",
                    "report_path": "r.json",
                    "applies_to": {"refs": refs},
                }
            ],
        }
    )


def test_nothing_applies_warns() -> None:
    result = evaluate(_scoped_policy(["release/*"]), PIPELINE, {})
    assert result.decision is Decision.VERIFIED
    assert any("nothing was verified" in w for w in result.warnings)


def test_matching_ref_is_evaluated() -> None:
    result = evaluate(_scoped_policy(["ma*"]), PIPELINE, {})
    assert result.decision is Decision.BLOCKED  # applies, and the job is absent


def test_gitlab_templates_example_policy_loads(monkeypatch) -> None:
    monkeypatch.setenv("RELEASE_IMAGE_DIGEST", DIGEST)
    policy = load_policy(EXAMPLE.parent / "gitlab-templates.yaml")
    assert [r.tool for r in policy.requirements] == ["gitlab-sast", "gitlab-container-scanning"]
