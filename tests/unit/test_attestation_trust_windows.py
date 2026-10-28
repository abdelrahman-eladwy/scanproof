"""#44: trust material must have been valid when the bundle was signed.

A Sigstore trusted root retires a Fulcio CA, a transparency log key or a CT log key by giving
its `validFor` window an `end`. sigstore-python 4.x checks those windows against the *current*
time and accepts expired material when verifying, so a bundle signed after the material was
retired verified. scanproof.attestation.windows checks every recorded signing time against the
windows of the material that vouches for it.

Offline: real bundles, and the real production trusted root with edited windows.
"""

from __future__ import annotations

import copy
import json

import pytest

pytest.importorskip("sigstore", reason="needs the attestations extra")

from scanproof.attestation import windows
from scanproof.attestation.models import AttestationStatus
from scanproof.attestation.verify import TrustConfig, verify_bundle
from tests.conftest import FIXTURES

A = FIXTURES / "attestations"
ROOT = json.loads((A / "trusted_root.production.json").read_text())
PROVENANCE = (A / "semgrep.provenance.sigstore.json").read_bytes()  # signed 2026-10-27T06:10:40Z
BLOB = (A / "semgrep.message-signature.sigstore.json").read_bytes()  # log + RFC 3161 time
REPORT_SHA = __import__("hashlib").sha256((A / "semgrep.json").read_bytes()).hexdigest()

BEFORE = "2026-10-27T06:00:00Z"  # before the provenance bundle was signed
AFTER = "2026-10-28T00:00:00Z"  # after it was signed (and in the past for these tests)

# The material each real bundle depends on: Fulcio CA #1, rekor.sigstore.dev, CT log 2022.
MATERIAL = {"ca": ("certificateAuthorities", 1), "tlog": ("tlogs", 0), "ctlog": ("ctlogs", 1)}
REASON = {
    "ca": "issuing certificate authority",
    "tlog": "transparency log key",
    "ctlog": "CT log key",
}


def root_with(tmp_path, kind: str, **window) -> TrustConfig:
    root = copy.deepcopy(ROOT)
    key, index = MATERIAL[kind]
    item = root[key][index]
    target = item["validFor"] if "validFor" in item else item["publicKey"]["validFor"]
    target.update(window)
    path = tmp_path / f"{kind}.json"
    path.write_text(json.dumps(root))
    return TrustConfig([path])


@pytest.mark.parametrize("kind", list(MATERIAL))
def test_material_retired_before_signing_is_rejected(tmp_path, kind) -> None:
    att = verify_bundle(PROVENANCE, root_with(tmp_path, kind, end=BEFORE))
    assert att.status is AttestationStatus.INVALID
    assert "not valid at signing time" in att.reason
    assert REASON[kind] in att.reason
    assert att.signer is None  # no claims are attached to a rejected bundle


@pytest.mark.parametrize("kind", list(MATERIAL))
def test_material_retired_after_signing_still_verifies(tmp_path, kind) -> None:
    """Rotation must not invalidate signatures made while the material was valid."""
    att = verify_bundle(PROVENANCE, root_with(tmp_path, kind, end=AFTER))
    assert att.status is AttestationStatus.VERIFIED


@pytest.mark.parametrize("kind", ["ca", "tlog"])
def test_material_valid_only_from_after_signing_is_rejected(tmp_path, kind) -> None:
    """The window starts after the signing time but before now: sigstore-python (which
    compares with now) accepts it; the signing-time check does not."""
    att = verify_bundle(PROVENANCE, root_with(tmp_path, kind, start="2026-10-27T07:00:00Z"))
    assert att.status is AttestationStatus.INVALID


def test_sigstore_python_alone_accepts_retired_material(tmp_path, monkeypatch) -> None:
    """Documents the upstream gap this check closes; fails if sigstore-python starts enforcing
    windows by signing time itself (then the check is defense in depth only)."""
    monkeypatch.setattr(windows, "check", lambda *a: (windows.OK, ""))
    att = verify_bundle(PROVENANCE, root_with(tmp_path, "ca", end=BEFORE))
    assert att.status is AttestationStatus.VERIFIED


def test_rfc3161_timestamps_are_checked_too(tmp_path) -> None:
    trust = root_with(tmp_path, "ca", end=BEFORE)
    att = verify_bundle(BLOB, trust, artifact_sha256=REPORT_SHA)
    assert att.status is AttestationStatus.INVALID
    assert len(windows.signing_times(json.loads(BLOB))) == 2  # log entry + RFC 3161 token


def test_built_in_production_root_has_its_windows_checked() -> None:
    trust = TrustConfig(offline=True)
    assert verify_bundle(PROVENANCE, trust).status is AttestationStatus.VERIFIED
    assert trust.root(0).get("certificateAuthorities")


# ---------------------------------------------------------------- check() on its own


def leaf():
    from sigstore.models import Bundle

    return Bundle.from_json(PROVENANCE).signing_certificate


def test_genuine_bundle_and_root_pass() -> None:
    assert windows.check(PROVENANCE, leaf(), ROOT) == (windows.OK, "")


def test_no_recorded_signing_time_is_unverifiable() -> None:
    doc = json.loads(PROVENANCE)
    for entry in doc["verificationMaterial"]["tlogEntries"]:
        entry["integratedTime"] = "0"
    status, reason = windows.check(json.dumps(doc).encode(), leaf(), ROOT)
    assert status == windows.UNVERIFIABLE
    assert "no signing time" in reason


def test_extra_forged_time_can_only_make_it_fail() -> None:
    doc = json.loads(PROVENANCE)
    forged = copy.deepcopy(doc["verificationMaterial"]["tlogEntries"][0])
    forged["integratedTime"] = "1"  # 1970: outside every window
    doc["verificationMaterial"]["tlogEntries"].append(forged)
    assert windows.check(json.dumps(doc).encode(), leaf(), ROOT)[0] == windows.INVALID


def test_log_entry_from_a_log_not_in_the_root_is_invalid() -> None:
    root = copy.deepcopy(ROOT)
    root["tlogs"] = [t for t in root["tlogs"] if t["baseUrl"] != "https://rekor.sigstore.dev"]
    status, reason = windows.check(PROVENANCE, leaf(), root)
    assert status == windows.INVALID
    assert "log not in the trust root" in reason


def test_certificate_not_issued_by_any_ca_in_the_root_is_invalid() -> None:
    staging = json.loads((A / "trusted_root.staging.json").read_text())
    root = copy.deepcopy(ROOT) | {"certificateAuthorities": staging["certificateAuthorities"]}
    status, reason = windows.check(PROVENANCE, leaf(), root)
    assert status == windows.INVALID
    assert "issued the signing certificate" in reason


@pytest.mark.parametrize(
    "root",
    [{"certificateAuthorities": "x"}, {"certificateAuthorities": [{"certChain": 5}]}, []],
    ids=["string", "bad-chain", "not-a-mapping"],
)
def test_unreadable_root_is_unverifiable_never_ok(root) -> None:
    status, _ = windows.check(PROVENANCE, leaf(), root)
    assert status in (windows.UNVERIFIABLE, windows.INVALID)
    assert status != windows.OK


def test_garbage_bundle_is_unverifiable() -> None:
    assert windows.check(b"{not json", leaf(), ROOT)[0] == windows.UNVERIFIABLE
