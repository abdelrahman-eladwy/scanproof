"""assurance.profile: production — load-time rejection of assurance-weakening opt-ins (#52).

Two contracts:
* Compatibility: a policy that does not select the profile loads exactly as before, opt-ins
  included. Every shipped example policy loads under both profiles.
* Production: every opt-in in the #52 table is a load error (exit 3) naming its code, and
  `validate --explain` reports the same list for any profile.

Out of scope here (tracked separately as Phase 1 detection work, not policy validation):
exact-name precedence in find_jobs and removed matrix legs.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from scanproof.cli import EXIT_OK, EXIT_USAGE, app
from scanproof.policy.models import Checks, Policy, PolicyError, load_policy
from scanproof.policy.profile import assurance_opt_ins, production_violations

EXAMPLES = sorted((Path(__file__).parents[2] / "examples/policies").glob("*.yaml"))
DIGEST = "sha256:" + "a" * 64
runner = CliRunner()

SIGNER = {
    "issuer": "https://token.actions.githubusercontent.com",
    "repository": "https://github.com/org/app",
    "workflow": r"https://github\.com/org/app/\.github/workflows/ci\.yml@refs/heads/main",
}


def base(provider: str = "gitlab") -> dict:
    """A policy with no opt-ins at all."""
    req = {"id": "SAST", "tool": "semgrep", "job_name": "sast", "report_path": "s.json"}
    if provider == "github":
        req["artifact_name"] = "semgrep-report"
    return {
        "apiVersion": "scanproof.dev/v1alpha1",
        "kind": "PipelineAssurancePolicy",
        "project": {"provider": provider, "id": "org/app"},
        "requirements": [req],
    }


def attested(**overrides) -> dict:
    body = base("github")
    body["requirements"][0]["attestation"] = {
        "source": "platform",
        "signer": dict(SIGNER),
        **overrides,
    }
    return body


def with_profile(body: dict, profile: str | None, **assurance) -> dict:
    body = copy.deepcopy(body)
    if profile is not None:
        assurance["profile"] = profile
    if assurance:
        body["assurance"] = assurance
    return body


def codes(policy: Policy) -> set[str]:
    return {o.code for o in production_violations(policy)}


def _checks(**checks) -> dict:
    body = base()
    body["requirements"][0]["checks"] = checks
    return body


def _waiver(**w) -> dict:
    body = base()
    body["waivers"] = [
        {
            "requirement": "SAST",
            "check": "scanner_errors",
            "reason": "ticket SEC-123: false positive",
            "approved_by": "security-lead",
            "expires": "2026-12-31",
            **w,
        }
    ]
    return body


def _bounded_waiver(**w) -> dict:
    body = _waiver(created="2026-12-01", **w)
    body["enforcement"] = {"max_waiver_days": 30}
    return body


def _signer_without_repository() -> dict:
    body = attested()
    del body["requirements"][0]["attestation"]["signer"]["repository"]
    body["requirements"][0]["attestation"]["signer"]["workflow"] = ".*"
    return body


# One row per #52 opt-in: (case id, policy body, exactly the codes it must raise).
# Each body changes as little as possible so a row tests one setting.
OPT_INS = [
    ("on_unknown_warn", {**base(), "enforcement": {"on_unknown": "warn"}}, {"ON_UNKNOWN_WARN"}),
    (
        "on_nothing_applicable_allow",
        {**base(), "enforcement": {"on_nothing_applicable": "allow"}},
        {"NOTHING_APPLICABLE_ALLOW"},
    ),
    ("job_success_false", _checks(job_success=False), {"JOB_SUCCESS_DISABLED"}),
    ("same_commit_false", _checks(same_commit=False), {"SAME_COMMIT_DISABLED"}),
    ("report_optional", _checks(report_required=False), {"REPORT_OPTIONAL"}),
    (
        "report_optional_drops_digest_check",
        _checks(report_required=False, image_digest_must_match=DIGEST),
        {"REPORT_OPTIONAL_DROPS_CHECKS"},
    ),
    (
        "report_optional_drops_file_count",
        _checks(report_required=False, minimum_scanned_files=1),
        {"REPORT_OPTIONAL_DROPS_CHECKS"},
    ),
    (
        "every_check_disabled",
        _checks(job_success=False, same_commit=False, report_required=False),
        {"JOB_SUCCESS_DISABLED", "SAME_COMMIT_DISABLED", "REPORT_OPTIONAL", "ALL_CHECKS_DISABLED"},
    ),
    (
        "attestation_same_commit_false",
        attested(same_commit=False),
        {"ATTESTATION_SAME_COMMIT_DISABLED"},
    ),
    ("attestation_same_run_false", attested(same_run=False), {"ATTESTATION_SAME_RUN_DISABLED"}),
    ("signer_workflow_only", _signer_without_repository(), {"SIGNER_REPOSITORY_UNPINNED"}),
    ("waiver_without_max_days", _waiver(), {"WAIVER_UNBOUNDED"}),
    ("waiver_far_future_expiry", _waiver(expires="9999-12-31"), {"WAIVER_UNBOUNDED"}),
    ("waiver_on_job_present", _bounded_waiver(check="job_present"), {"WAIVER_REMOVES_REQUIREMENT"}),
    (
        "waiver_on_job_present_with_code",
        _bounded_waiver(check="job_present", code="REQUIRED_JOB_ABSENT"),
        {"WAIVER_REMOVES_REQUIREMENT"},
    ),
    (
        "waiver_on_job_present_instance",
        _bounded_waiver(check="job_present [py]"),
        {"WAIVER_REMOVES_REQUIREMENT"},
    ),
]
OPT_IN_IDS = [case[0] for case in OPT_INS]


# ---------------------------------------------------------------- compatibility


@pytest.fixture
def example_env(monkeypatch):
    monkeypatch.setenv("RELEASE_IMAGE_DIGEST", DIGEST)
    monkeypatch.setenv("DEPLOY_URL", "https://staging.example.com")


@pytest.mark.parametrize("path", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_example_policy_loads_unchanged_and_defaults_to_compatible(path, example_env) -> None:
    policy = load_policy(path)
    assert policy.assurance.profile == "compatible"


@pytest.mark.parametrize("path", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_example_policy_also_satisfies_production(path, example_env, tmp_path) -> None:
    """The shipped examples are the reference policies: they must not need weakening."""
    body = yaml.safe_load(path.read_text())
    body.setdefault("assurance", {})["profile"] = "production"
    strict = tmp_path / path.name
    strict.write_text(yaml.safe_dump(body))
    assert load_policy(strict).assurance.profile == "production"


@pytest.mark.parametrize(("case", "body", "expected"), OPT_INS, ids=OPT_IN_IDS)
@pytest.mark.parametrize("profile", [None, "compatible"])
def test_opt_in_still_loads_without_production_profile(case, body, expected, profile) -> None:
    """Backward compatibility: no opt-in is rejected unless the policy selects production."""
    policy = Policy.model_validate(with_profile(body, profile))
    assert policy.assurance.profile == "compatible"
    assert codes(policy) == expected  # --explain still reports it


def test_reported_scope_alone_keeps_its_previous_rules() -> None:
    """reported_scope did not gain the production rules: same_commit: false still loads."""
    body = with_profile(_checks(same_commit=False), None, minimum_level="reported_scope")
    assert Policy.model_validate(body).assurance.minimum_level == "reported_scope"


def test_unknown_profile_is_rejected() -> None:
    with pytest.raises(ValueError, match="profile"):
        Policy.model_validate(with_profile(base(), "strict"))


# ---------------------------------------------------------------- production rejections


@pytest.mark.parametrize(("case", "body", "expected"), OPT_INS, ids=OPT_IN_IDS)
def test_production_rejects_opt_in(case, body, expected) -> None:
    with pytest.raises(ValueError) as exc:
        Policy.model_validate(with_profile(body, "production"))
    message = str(exc.value)
    assert "assurance.profile: production rejects" in message
    for code in expected:
        assert f"[{code}]" in message


@pytest.mark.parametrize(
    "body",
    [
        base(),
        base("github"),
        attested(),
        _bounded_waiver(),
        _checks(max_age_hours=24, minimum_scanned_files=1),
        with_profile(base(), None, minimum_level="reported_scope"),
    ],
    ids=["minimal", "github", "attested", "bounded-waiver", "extra-checks", "reported-scope"],
)
def test_production_accepts_policy_without_opt_ins(body) -> None:
    assurance = dict(body.get("assurance", {}))
    policy = Policy.model_validate(with_profile(body, "production", **assurance))
    assert policy.assurance.profile == "production"
    assert production_violations(policy) == []


def test_production_reports_every_violation_at_once() -> None:
    body = _checks(job_success=False, same_commit=False)
    body["enforcement"] = {"on_unknown": "warn"}
    with pytest.raises(ValueError) as exc:
        Policy.model_validate(with_profile(body, "production"))
    message = str(exc.value)
    assert "rejects 3 setting(s)" in message
    assert all(
        f"[{c}]" in message
        for c in ("ON_UNKNOWN_WARN", "JOB_SUCCESS_DISABLED", "SAME_COMMIT_DISABLED")
    )


def test_production_rejection_is_a_policy_error(tmp_path) -> None:
    path = tmp_path / "weak.yaml"
    path.write_text(yaml.safe_dump(with_profile(_checks(job_success=False), "production")))
    with pytest.raises(PolicyError, match=r"JOB_SUCCESS_DISABLED"):
        load_policy(path)


def test_production_and_reported_scope_combine() -> None:
    body = with_profile(_checks(job_success=False), "production", minimum_level="reported_scope")
    with pytest.raises(ValueError, match="JOB_SUCCESS_DISABLED"):
        Policy.model_validate(body)


def test_attestation_or_freshness_keeps_requirement_from_being_empty() -> None:
    """ALL_CHECKS_DISABLED only when the outcome really is NOT_APPLICABLE whatever happens."""
    for extra in ({"max_age_hours": 24}, {"minimum_scanned_files": 1}):
        body = _checks(job_success=False, same_commit=False, report_required=False, **extra)
        assert "ALL_CHECKS_DISABLED" not in codes(Policy.model_validate(body))
    body = attested()
    body["requirements"][0]["checks"] = {
        "job_success": False,
        "same_commit": False,
        "report_required": False,
    }
    assert "ALL_CHECKS_DISABLED" not in codes(Policy.model_validate(body))


def test_waiver_on_other_check_is_allowed_when_bounded() -> None:
    assert codes(Policy.model_validate(_bounded_waiver(check="job_success"))) == set()


def test_gitlab_same_run_is_a_note_not_a_rejection() -> None:
    body = base()
    body["requirements"][0]["attestation"] = {
        "source": "artifact",
        "bundle_path": "s.sigstore.json",
        "signer": {"issuer": "https://gitlab.com", "repository": "https://gitlab.com/org/app"},
    }
    policy = Policy.model_validate(with_profile(body, "production"))
    notes = [o for o in assurance_opt_ins(policy) if o.production == "note"]
    assert [o.code for o in notes] == ["GITLAB_SAME_RUN_IS_PIPELINE_WIDE"]


# ---------------------------------------------------------------- one list for engine and profile

# Checks fields that do not read the report. Every other field must appear in
# Checks.evidence_checks(), or report_required: false could drop it unreported.
NOT_EVIDENCE = {
    "job_success",
    "same_commit",
    "report_required",
    "ignore_scanner_warnings",
    "max_age_hours",
    "same_target_as",
}
EVIDENCE_SAMPLES = {
    "scanner_errors_allowed": 0,
    "minimum_scanned_files": 1,
    "required_paths": ["src/"],
    "image_digest_must_match": DIGEST,
    "expected_scanner": "CodeQL",
    "minimum_components": 1,
    "minimum_resources": 1,
    "target_url_must_match": "https://staging.example.com",
    "minimum_endpoints": 1,
}


def test_every_evidence_check_is_listed() -> None:
    assert set(EVIDENCE_SAMPLES) == set(Checks.model_fields) - NOT_EVIDENCE, (
        "new Checks field: classify it in NOT_EVIDENCE or add it to Checks.evidence_checks()"
    )
    for name, value in EVIDENCE_SAMPLES.items():
        assert Checks(**{name: value}).evidence_checks() == [name]
    assert Checks().evidence_checks() == []


# ---------------------------------------------------------------- validate --explain


def _write(tmp_path, body) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(body))
    return str(path)


def test_validate_without_explain_is_unchanged(tmp_path) -> None:
    result = runner.invoke(app, ["validate", "-P", _write(tmp_path, _checks(job_success=False))])
    assert result.exit_code == EXIT_OK
    assert "profile:" not in result.stderr
    assert "JOB_SUCCESS_DISABLED" not in result.stderr


def test_explain_clean_policy(tmp_path) -> None:
    result = runner.invoke(app, ["validate", "--explain", "-P", _write(tmp_path, base())])
    assert result.exit_code == EXIT_OK
    assert "profile: compatible" in result.stderr
    assert "No assurance-weakening opt-ins." in result.stderr


@pytest.mark.parametrize(("case", "body", "expected"), OPT_INS, ids=OPT_IN_IDS)
def test_explain_lists_every_opt_in(case, body, expected, tmp_path) -> None:
    result = runner.invoke(app, ["validate", "--explain", "-P", _write(tmp_path, body)])
    assert result.exit_code == EXIT_OK, result.stderr
    for code in expected:
        assert f"- {code} at " in result.stderr
    assert f"{len(expected)} assurance-weakening opt-in(s)" in result.stderr


def test_explain_shows_notes_separately(tmp_path) -> None:
    body = base()
    body["requirements"][0]["attestation"] = {
        "source": "artifact",
        "bundle_path": "s.sigstore.json",
        "signer": {"issuer": "https://gitlab.com", "repository": "https://gitlab.com/org/app"},
    }
    result = runner.invoke(
        app, ["validate", "--explain", "-P", _write(tmp_path, with_profile(body, "production"))]
    )
    assert result.exit_code == EXIT_OK, result.stderr
    assert "profile: production" in result.stderr
    assert "No assurance-weakening opt-ins." in result.stderr
    assert "note GITLAB_SAME_RUN_IS_PIPELINE_WIDE" in result.stderr


def test_validate_production_weak_policy_exits_usage(tmp_path) -> None:
    path = _write(tmp_path, with_profile(_checks(same_commit=False), "production"))
    for args in (["validate", "-P", path], ["validate", "--explain", "-P", path]):
        result = runner.invoke(app, args)
        assert result.exit_code == EXIT_USAGE
        assert "SAME_COMMIT_DISABLED" in result.stderr
