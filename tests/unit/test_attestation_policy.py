"""Attestation policy model and the pure engine checks (no crypto: evidence is constructed)."""

from __future__ import annotations

import pytest

from scanproof.attestation.models import (
    AttestationEvidence,
    AttestationStatus,
    SignerClaims,
    Subject,
)
from scanproof.evidence.models import ScanEvidence, ScanType
from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.engine import Outcome, RequirementInput, evaluate_requirement
from scanproof.policy.models import Policy, Requirement

SHA = "a" * 40
DIGEST = "b" * 64
ISSUER = "https://token.actions.githubusercontent.com"
REPO = "https://github.com/org/app"
SIGNER = f"{REPO}/.github/workflows/ci.yml@refs/heads/main"
PIPE = Pipeline(id=7, sha=SHA, ref="main", status="success")


def requirement(**attestation) -> Requirement:
    spec = {
        "source": "artifact",
        "bundle_path": "r.sigstore.json",
        "signer": {"issuer": ISSUER, "repository": REPO, "workflow": r".*/ci\.yml@refs/heads/main"},
        **attestation,
    }
    return Requirement.model_validate(
        {
            "id": "R",
            "tool": "semgrep",
            "job_name": "sast",
            "report_path": "r.json",
            "checks": {"report_required": True},
            "attestation": spec,
        }
    )


def verified(**over) -> AttestationEvidence:
    signer = {
        "issuer": ISSUER,
        "build_signer_uri": SIGNER,
        "source_repository_uri": REPO,
        "source_repository_digest": SHA,
        "run_invocation_uri": f"{REPO}/actions/runs/7/attempts/1",
        **over.pop("signer", {}),
    }
    base = {
        "status": AttestationStatus.VERIFIED,
        "predicate_type": "https://slsa.dev/provenance/v1",
        "subjects": [Subject(name="r.json", digest={"sha256": DIGEST})],
        "signer": SignerClaims(**signer),
        "run_matches": True,
    }
    return AttestationEvidence(**(base | over))


def run(req: Requirement, attestations=None, error=None, *, unvalidated=False):
    job = Job(id=1, name="sast", status=JobStatus.SUCCESS, commit_sha=SHA)
    inspected = InspectedJob(name="sast", stage=None, latest=job, attempt_ids=[1])
    ev = ScanEvidence(
        tool="semgrep",
        scan_type=ScanType.SAST,
        present=True,
        parseable=True,
        report_sha256=DIGEST,
        report_bytes=10,
    )
    make = RequirementInput.model_construct if unvalidated else RequirementInput
    data = make(job=inspected, evidence=ev, attestations=attestations, attestation_error=error)
    res = evaluate_requirement(req, PIPE, data)
    (check,) = [c for c in res.checks if c.check == "attestation"]
    return check


# ---------------------------------------------------------------- policy model


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"signer": {"issuer": ISSUER}}, "must pin repository and/or workflow"),
        ({"signer": {"issuer": ISSUER, "workflow": "("}}, "not a valid regex"),
        ({"bundle_path": None}, "needs bundle_path"),
        ({"source": "platform"}, "only used with source: artifact"),
        ({"signer": {"issuer": ISSUER, "repository": REPO, "extra": 1}}, "Extra inputs"),
    ],
)
def test_invalid_attestation_specs(spec, message) -> None:
    with pytest.raises(ValueError, match=message):
        requirement(**spec)


def test_image_subject_needs_a_digest() -> None:
    with pytest.raises(ValueError, match="image_digest_must_match"):
        requirement(subject="image")


def _policy(provider: str, **spec) -> dict:
    return {
        "apiVersion": "scanproof.dev/v1alpha1",
        "kind": "PipelineAssurancePolicy",
        "project": {"provider": provider, "id": "org/app"},
        "requirements": [
            {
                "id": "R",
                "tool": "semgrep",
                "job_name": "sast",
                "report_path": "r.json",
                "artifact_name": "a",
                "attestation": {"signer": {"issuer": ISSUER, "repository": REPO}, **spec},
            }
        ],
    }


def test_gitlab_has_no_attestation_store() -> None:
    with pytest.raises(ValueError, match="gitlab has no attestation store"):
        Policy.model_validate(_policy("gitlab", source="platform"))
    Policy.model_validate(_policy("gitlab", source="artifact", bundle_path="b.json"))
    Policy.model_validate(_policy("github", source="platform"))


# ---------------------------------------------------------------- engine


def test_accepted() -> None:
    check = run(requirement(), [verified()])
    assert (check.outcome, check.code) == (Outcome.PASS, "ATTESTATION_VERIFIED")


@pytest.mark.parametrize(
    ("att", "code", "outcome"),
    [
        (
            AttestationEvidence(status=AttestationStatus.INVALID, reason="bad sig"),
            "ATTESTATION_INVALID",
            Outcome.FAIL,
        ),
        (
            AttestationEvidence(status=AttestationStatus.UNVERIFIABLE, reason="no sigstore"),
            "ATTESTATION_UNVERIFIABLE",
            Outcome.UNKNOWN,
        ),
        (
            verified(subjects=[Subject(digest={"sha256": "c" * 64})]),
            "ATTESTATION_SUBJECT_MISMATCH",
            Outcome.FAIL,
        ),
        (
            verified(subjects=[Subject(digest={"sha512": DIGEST})]),
            "ATTESTATION_SUBJECT_MISMATCH",
            Outcome.FAIL,
        ),
        (
            verified(predicate_type="https://example.com/other"),
            "ATTESTATION_PREDICATE_MISMATCH",
            Outcome.FAIL,
        ),
        (
            verified(signer={"issuer": "https://gitlab.com"}),
            "ATTESTATION_SIGNER_MISMATCH",
            Outcome.FAIL,
        ),
        (
            verified(signer={"source_repository_uri": "https://github.com/evil/app"}),
            "ATTESTATION_SIGNER_MISMATCH",
            Outcome.FAIL,
        ),
        (
            verified(signer={"build_signer_uri": f"{REPO}/.github/workflows/ci.yml@refs/heads/x"}),
            "ATTESTATION_SIGNER_MISMATCH",
            Outcome.FAIL,
        ),
        (
            # prefix match is not enough: the regex must match the WHOLE Build Signer URI
            verified(signer={"build_signer_uri": SIGNER + "-evil"}),
            "ATTESTATION_SIGNER_MISMATCH",
            Outcome.FAIL,
        ),
        (
            verified(signer={"source_repository_digest": "d" * 40}),
            "ATTESTATION_WRONG_COMMIT",
            Outcome.FAIL,
        ),
        (verified(run_matches=False), "ATTESTATION_WRONG_RUN", Outcome.FAIL),
        (verified(run_matches=None), "ATTESTATION_RUN_UNKNOWN", Outcome.UNKNOWN),
        (
            verified(signer={"source_repository_digest": None}),
            "ATTESTATION_CLAIM_MISSING",
            Outcome.UNKNOWN,
        ),
        (
            verified(signer={"build_signer_uri": None}),
            "ATTESTATION_CLAIM_MISSING",
            Outcome.UNKNOWN,
        ),
    ],
)
def test_rejections(att, code, outcome) -> None:
    check = run(requirement(), [att])
    assert (check.code, check.outcome) == (code, outcome), check.message


def test_repository_comparison_ignores_case_and_trailing_slash() -> None:
    att = verified(signer={"source_repository_uri": "https://github.com/ORG/App/"})
    assert run(requirement(), [att]).outcome is Outcome.PASS


def test_same_commit_and_run_can_be_relaxed() -> None:
    att = verified(run_matches=False, signer={"source_repository_digest": "d" * 40})
    assert run(requirement(same_commit=False, same_run=False), [att]).outcome is Outcome.PASS


def test_missing_and_unavailable() -> None:
    assert run(requirement(), []).code == "ATTESTATION_MISSING"
    assert (run(requirement(), None).code, run(requirement(), None).outcome) == (
        "ATTESTATION_NOT_CHECKED",
        Outcome.UNKNOWN,
    )
    check = run(requirement(), None, error="HTTP 403")
    assert (check.code, check.outcome) == ("ATTESTATION_UNAVAILABLE", Outcome.UNKNOWN)


def test_one_acceptable_bundle_among_several_is_enough() -> None:
    old_run = verified(run_matches=False)
    check = run(requirement(), [old_run, verified()])
    assert check.outcome is Outcome.PASS
    assert "1 of 2 bundles" in check.message


def test_no_acceptable_bundle_lists_each_reason() -> None:
    check = run(requirement(), [verified(run_matches=False), verified(predicate_type="x")])
    assert check.outcome is Outcome.FAIL
    assert "[1] ATTESTATION_WRONG_RUN" in check.message
    assert "[2] ATTESTATION_PREDICATE_MISMATCH" in check.message


def test_unknown_only_when_nothing_failed() -> None:
    check = run(requirement(), [verified(run_matches=None), verified(run_matches=None)])
    assert check.outcome is Outcome.UNKNOWN


def test_engine_rejects_claims_on_an_unverified_bundle_even_if_the_model_is_bypassed() -> None:
    """Second layer behind the model validator: the engine itself requires VERIFIED."""
    forged = verified().model_copy(update={"status": AttestationStatus.INVALID})
    forged = AttestationEvidence.model_construct(**dict(forged))
    check = run(requirement(), [forged], unvalidated=True)
    assert (check.code, check.outcome) == ("ATTESTATION_INVALID", Outcome.FAIL)


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("sigstore") is not None,
    reason="only meaningful without the attestations extra (ci.yml lowest-deps / core)",
)
def test_without_the_extra_bundles_are_unverifiable_not_valid() -> None:
    from scanproof.attestation.verify import TrustConfig, verify_bundle
    from tests.conftest import FIXTURES

    raw = (FIXTURES / "attestations/semgrep.provenance.sigstore.json").read_bytes()
    att = verify_bundle(raw, TrustConfig())
    assert att.status is AttestationStatus.UNVERIFIABLE
    assert "scanproof[attestations]" in att.reason
