"""Sigstore verification against real bundles, and forgeries made by editing them.

Offline: the trust root is pinned in tests/fixtures/attestations/.
"""

from __future__ import annotations

import base64
import builtins
import hashlib
import json
import random

import pytest

pytest.importorskip("sigstore", reason="needs the attestations extra")

from scanproof.attestation.models import AttestationEvidence, AttestationStatus, SignerClaims
from scanproof.attestation.verify import (
    MESSAGE_SIGNATURE,
    TrustConfig,
    _der_utf8,
    split_bundles,
    verify_bundle,
    verify_bundles,
)
from tests.conftest import FIXTURES

A = FIXTURES / "attestations"
REPORT = (A / "semgrep.json").read_bytes()
REPORT_SHA = hashlib.sha256(REPORT).hexdigest()
IMAGE_SHA = "d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
RUN = dict(kv.split("=") for kv in (A / "run.txt").read_text().split())
PROVENANCE = (A / "semgrep.provenance.sigstore.json").read_bytes()
REUSABLE = (A / "semgrep.reusable.sigstore.json").read_bytes()
BLOB = (A / "semgrep.message-signature.sigstore.json").read_bytes()
VULN = (A / "image.vuln.sigstore.json").read_bytes()
REPO = "https://github.com/abdelrahman-eladwy/scanproof"
WF = f"{REPO}/.github/workflows"


@pytest.fixture(scope="module")
def trust() -> TrustConfig:
    return TrustConfig([A / "trusted_root.production.json"])


def edit(raw: bytes, change) -> bytes:
    doc = json.loads(raw)
    change(doc)
    return json.dumps(doc).encode()


# ---------------------------------------------------------------- genuine bundles


def test_slsa_provenance_for_a_report(trust) -> None:
    att = verify_bundle(PROVENANCE, trust)
    assert att.status is AttestationStatus.VERIFIED, att.reason
    assert att.predicate_type == "https://slsa.dev/provenance/v1"
    assert att.subject_digests() == {REPORT_SHA}
    s = att.signer
    assert s.issuer == "https://token.actions.githubusercontent.com"
    assert s.build_signer_uri == f"{WF}/attestation-contract.yml@refs/heads/fixtures/attest/run"
    assert s.source_repository_uri == REPO
    assert s.source_repository_digest == RUN["sha"]
    assert s.run_invocation_uri == f"{REPO}/actions/runs/{RUN['run_id']}/attempts/1"
    assert att.predicate_summary["builder_id"].startswith("https://github.com/")


def test_reusable_workflow_signer_differs_from_build_config(trust) -> None:
    s = verify_bundle(REUSABLE, trust).signer
    assert s.build_signer_uri == f"{WF}/reusable-attest.yml@refs/heads/fixtures/attest/run"
    assert s.build_config_uri == f"{WF}/attestation-contract.yml@refs/heads/fixtures/attest/run"


def test_cosign_vuln_attestation_on_an_image(trust) -> None:
    att = verify_bundle(VULN, trust)
    assert att.status is AttestationStatus.VERIFIED, att.reason
    assert att.predicate_type == "https://cosign.sigstore.dev/attestation/vuln/v1"
    assert att.subject_digests() == {IMAGE_SHA}
    assert att.predicate_summary["scanner_uri"] == "pkg:github/aquasecurity/trivy@v0.76.1"


def test_message_signature_over_the_report(trust) -> None:
    att = verify_bundle(BLOB, trust, artifact_sha256=REPORT_SHA)
    assert att.status is AttestationStatus.VERIFIED, att.reason
    assert att.predicate_type == MESSAGE_SIGNATURE
    assert att.subject_digests() == {REPORT_SHA}
    assert att.signer.build_signer_uri.startswith(f"{WF}/attestation-contract.yml@")


def test_message_signature_does_not_verify_other_bytes(trust) -> None:
    other = hashlib.sha256(REPORT + b" ").hexdigest()
    att = verify_bundle(BLOB, trust, artifact_sha256=other)
    assert att.status is AttestationStatus.INVALID
    assert att.signer is None


def test_message_signature_without_the_artifact_is_unverifiable(trust) -> None:
    assert verify_bundle(BLOB, trust).status is AttestationStatus.UNVERIFIABLE


def test_github_attestations_reply_with_bundles_from_two_runs(trust) -> None:
    raw = (A / f"github-attestations-{IMAGE_SHA[:12]}.json").read_bytes()
    atts = verify_bundles(raw, trust)
    assert len(atts) == 2
    assert all(a.status is AttestationStatus.VERIFIED for a in atts)
    runs = {a.signer.run_invocation_uri.split("/runs/")[1].split("/")[0] for a in atts}
    assert RUN["run_id"] in runs and len(runs) == 2


def test_json_lines_of_bundles(trust) -> None:
    raw = b"\n".join(json.dumps(json.loads(b)).encode() for b in (PROVENANCE, REUSABLE, VULN))
    assert [a.status for a in verify_bundles(raw, trust)] == [AttestationStatus.VERIFIED] * 3


def test_any_of_several_trusted_roots_is_enough(tmp_path) -> None:
    both = tmp_path / "roots.jsonl"
    both.write_text(
        "\n".join(
            json.dumps(json.loads((A / f"trusted_root.{n}.json").read_text()))
            for n in ("staging", "production")
        )
    )
    att = verify_bundle(PROVENANCE, TrustConfig([both]))
    assert att.status is AttestationStatus.VERIFIED, att.reason


# ---------------------------------------------------------------- forgeries


def _statement(doc):
    return json.loads(base64.b64decode(doc["dsseEnvelope"]["payload"]))


def _set_statement(doc, statement):
    doc["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()


def test_edited_subject_digest_breaks_the_signature(trust) -> None:
    """The obvious attack: re-point a genuine attestation at a different report."""

    def change(doc):
        st = _statement(doc)
        st["subject"][0]["digest"]["sha256"] = "0" * 64
        _set_statement(doc, st)

    att = verify_bundle(edit(PROVENANCE, change), trust)
    assert att.status is AttestationStatus.INVALID
    assert att.subjects == [] and att.signer is None


def test_edited_predicate_type_breaks_the_signature(trust) -> None:
    def change(doc):
        st = _statement(doc)
        st["predicateType"] = "https://cosign.sigstore.dev/attestation/vuln/v1"
        _set_statement(doc, st)

    assert verify_bundle(edit(PROVENANCE, change), trust).status is AttestationStatus.INVALID


def test_flipped_signature_byte(trust) -> None:
    def change(doc):
        sig = bytearray(base64.b64decode(doc["dsseEnvelope"]["signatures"][0]["sig"]))
        sig[-1] ^= 1
        doc["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()

    assert verify_bundle(edit(PROVENANCE, change), trust).status is AttestationStatus.INVALID


def test_certificate_swapped_in_from_another_bundle(trust) -> None:
    """Claim the reusable workflow's identity for the caller's signature (or vice versa)."""
    other = json.loads(REUSABLE)["verificationMaterial"]

    def change(doc):
        doc["verificationMaterial"]["certificate"] = other["certificate"]

    assert verify_bundle(edit(PROVENANCE, change), trust).status is AttestationStatus.INVALID


def test_transparency_log_entry_removed(trust) -> None:
    def change(doc):
        doc["verificationMaterial"]["tlogEntries"] = []

    assert verify_bundle(edit(PROVENANCE, change), trust).status is AttestationStatus.INVALID


def test_untrusted_sigstore_instance(tmp_path) -> None:
    att = verify_bundle(PROVENANCE, TrustConfig([A / "trusted_root.staging.json"]))
    assert att.status is AttestationStatus.INVALID
    assert "signature verification failed" in att.reason


def test_not_in_toto_payload_type(trust) -> None:
    def change(doc):
        doc["dsseEnvelope"]["payloadType"] = "text/plain"

    # payloadType is covered by the DSSE signature (PAE), so this fails as a signature error
    assert verify_bundle(edit(PROVENANCE, change), trust).status is AttestationStatus.INVALID


# ---------------------------------------------------------------- robustness


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"null",
        b"[]",
        b"{}",
        b"\xff\xfe",
        b'{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}',
        b'{"attestations": "nope"}',
        b'{"attestations": [{"bundle": 1}]}',
        b"[" * 100_000,
        PROVENANCE[: len(PROVENANCE) // 2],
        PROVENANCE.replace(b'"dsseEnvelope"', b'"dsseEnvelopX"'),
    ],
)
def test_garbage_never_raises(trust, raw) -> None:
    atts = verify_bundles(raw, trust)
    assert all(a.status is not AttestationStatus.VERIFIED for a in atts)
    assert all(a.signer is None for a in atts)


def test_attestations_reply_with_no_bundles() -> None:
    assert split_bundles(b'{"attestations": []}') == []


def test_sigstore_not_installed(monkeypatch) -> None:
    real_import = builtins.__import__

    def no_sigstore(name, *args, **kwargs):
        if name == "sigstore" or name.startswith("sigstore."):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_sigstore)
    att = verify_bundle(PROVENANCE, TrustConfig([A / "trusted_root.production.json"]))
    assert att.status is AttestationStatus.UNVERIFIABLE
    assert "scanproof[attestations]" in att.reason


def test_broken_trust_root_file(tmp_path) -> None:
    bad = tmp_path / "root.json"
    bad.write_text('{"mediaType": "nope"}')
    att = verify_bundle(PROVENANCE, TrustConfig([bad]))
    assert att.status is AttestationStatus.UNVERIFIABLE
    assert "trust root" in att.reason


def test_claims_cannot_be_attached_to_an_unverified_bundle() -> None:
    with pytest.raises(ValueError, match="only allowed on a verified"):
        AttestationEvidence(status=AttestationStatus.INVALID, signer=SignerClaims(issuer="x"))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"\x0c\x03abc", "abc"),
        (b"\x0c\x81\x03abc", "abc"),
        (b"\x0c\x04abc", None),  # length mismatch
        (b"\x13\x03abc", None),  # PrintableString, not UTF8String
        (b"\x0c\x80", None),  # indefinite length is not DER
        (b"\x0c\x02\xff\xfe", None),  # not UTF-8
        (b"", None),
    ],
)
def test_der_utf8(raw, expected) -> None:
    assert _der_utf8(raw) == expected


# ---------------------------------------------------------------- fuzz


def _claims(att: AttestationEvidence):
    return (att.predicate_type, att.subject_digests(), att.signer)


def _structural_mutations(rng, doc):
    """Replace one JSON value anywhere in the bundle with something odd."""
    paths = []

    def walk(obj, prefix):
        paths.append(prefix)
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, (*prefix, k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, (*prefix, i))

    walk(doc, ())
    path = rng.choice(paths[1:])
    target = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = rng.choice([None, 0, "", "AAAA", [], {}, "x" * 500, -1, True])
    return doc


@pytest.mark.parametrize("name", ["semgrep.provenance.sigstore.json", "image.vuln.sigstore.json"])
def test_fuzzed_bundles_never_raise_and_never_change_claims(trust, name) -> None:
    raw = (A / name).read_bytes()
    original = _claims(verify_bundle(raw, trust))
    rng = random.Random(1234)  # noqa: S311 - seeded fuzzing, not cryptography
    for _ in range(400):
        if rng.random() < 0.5:
            data = bytearray(raw)
            for _ in range(rng.randint(1, 4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            mutated = bytes(data)
        else:
            mutated = json.dumps(_structural_mutations(rng, json.loads(raw))).encode()
        att = verify_bundle(mutated, trust)  # must not raise
        if att.status is AttestationStatus.VERIFIED:
            # only edits outside the signed material can still verify, and then nothing
            # ScanProof judges may differ
            assert _claims(att) == original


# ---------------------------------------------------------------- statement parsing
# Reached only with a validly signed but malformed statement, so tested directly.

ST = "https://in-toto.io/Statement/v1"


@pytest.mark.parametrize(
    ("doc", "error"),
    [
        ([], "not an object"),
        ({"_type": "x"}, "unsupported statement type"),
        ({"_type": ST, "predicateType": ""}, "no predicateType"),
        ({"_type": ST, "predicateType": "p", "subject": []}, "no subjects"),
        ({"_type": ST, "predicateType": "p", "subject": [{"name": "a"}]}, "without a digest"),
        ({"_type": ST, "predicateType": "p", "subject": ["x"]}, "without a digest"),
    ],
)
def test_malformed_statements(doc, error) -> None:
    from scanproof.attestation.verify import _parse_statement

    assert error in _parse_statement(doc)


def test_statement_digests_are_normalized() -> None:
    from scanproof.attestation.verify import _parse_statement

    doc = {"_type": ST, "predicateType": "p", "subject": [{"name": 5, "digest": {"SHA256": "AB"}}]}
    _, _, subjects = _parse_statement(doc)
    assert subjects[0].digest == {"sha256": "ab"} and subjects[0].name is None


@pytest.mark.parametrize(
    "predicate",
    [None, [], {}, {"buildDefinition": 1}, {"runDetails": {"builder": {"id": {"x": 1}}}}],
)
def test_predicate_summary_tolerates_anything(predicate) -> None:
    from scanproof.attestation.verify import _summarize

    assert isinstance(_summarize("https://slsa.dev/provenance/v1", predicate), dict)
    assert _summarize("https://cosign.sigstore.dev/attestation/vuln/v1", predicate) == {}


def test_split_bundles_limits(monkeypatch) -> None:
    from scanproof.attestation import verify as v

    with pytest.raises(v.BundleFormatError, match="limit"):
        split_bundles(b" " * (v.MAX_BUNDLE_BYTES + 1))
    many = b"\n".join([json.dumps(json.loads(PROVENANCE)).encode()] * (v.MAX_BUNDLES + 1))
    with pytest.raises(v.BundleFormatError, match="at most"):
        split_bundles(many)
    with pytest.raises(v.BundleFormatError, match="neither"):
        split_bundles(b'{"hello": 1}')
