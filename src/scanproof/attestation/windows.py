"""Signing time must fall inside the validity window of the trust material that vouches for it.

A Sigstore trusted root gives every Fulcio CA, transparency log key and CT log key a `validFor`
window. Retiring material (rotation, or a compromise) sets its `end`. sigstore-python 4.x
compares those windows with the *current* time and deliberately accepts expired material when
verifying, so it never checks that a bundle was signed while the material was valid: a
signature made after a CA or log key was retired still verifies.

This module adds that check after sigstore-python has verified the bundle. Every time the
bundle records must fall inside the window of the material that vouches for it:

- signing times (each log entry's integrated time, each RFC 3161 timestamp) inside the window of
  a Fulcio CA that directly issued the signing certificate, and of the transparency log of
  each log entry;
- each embedded SCT's timestamp inside the window of its CT log.

Using every recorded time is sound: sigstore-python already required at least one *verified*
time, which is among them, and extra (even forged) times can only make the check fail.

Pure: no I/O. Returns (status, reason) with status "ok", "invalid" (outside a window, or the
material isn't in the root) or "unverifiable" (the check itself could not be carried out).
Timestamp authorities' own windows are not checked here.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

OK, INVALID, UNVERIFIABLE = "ok", "invalid", "unverifiable"


def _when(text: str | None) -> datetime | None:
    if not text:
        return None
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _inside(window: dict | None, times: list[datetime]) -> bool:
    if not window:
        return True  # no window: valid at all times (as in the Sigstore spec)
    start, end = _when(window.get("start")), _when(window.get("end"))
    return all((start is None or t >= start) and (end is None or t <= end) for t in times)


def _window(item: dict) -> dict | None:
    return item.get("validFor") or (item.get("publicKey") or {}).get("validFor")


def _key_id(item: dict) -> bytes | None:
    raw = (item.get("logId") or {}).get("keyId")
    return base64.b64decode(raw) if raw else None


def _fmt(times: list[datetime]) -> str:
    return ", ".join(sorted({t.strftime("%Y-%m-%dT%H:%M:%SZ") for t in times}))


def signing_times(bundle: dict) -> list[datetime]:
    """Every time the bundle records: nonzero log integrated times and RFC 3161 gen times."""
    from rfc3161_client import decode_timestamp_response

    material = bundle.get("verificationMaterial") or {}
    times = [
        datetime.fromtimestamp(int(entry["integratedTime"]), UTC)
        for entry in material.get("tlogEntries") or []
        if int(entry.get("integratedTime") or 0) > 0
    ]
    tsa = (material.get("timestampVerificationData") or {}).get("rfc3161Timestamps") or []
    for item in tsa:
        response = decode_timestamp_response(base64.b64decode(item["signedTimestamp"]))
        gen = response.tst_info.gen_time
        times.append(gen if gen.tzinfo else gen.replace(tzinfo=UTC))
    return times


def check(bundle_json: bytes, leaf: Any, root: dict) -> tuple[str, str]:
    """`leaf` is the verified signing certificate (cryptography x509), `root` the trusted root
    (as a dict) of the verifier that accepted the bundle."""
    from cryptography import x509

    try:
        bundle = json.loads(bundle_json)
        times = signing_times(bundle)
    except Exception as exc:
        return UNVERIFIABLE, f"cannot read the bundle's signing times: {type(exc).__name__}"
    if not times:
        return UNVERIFIABLE, "the bundle records no signing time to check against the trust root"
    when = _fmt(times)

    try:
        issuers = [
            ca
            for ca in root.get("certificateAuthorities") or []
            for cert in (ca.get("certChain") or {}).get("certificates") or []
            if _issued_by(leaf, x509.load_der_x509_certificate(base64.b64decode(cert["rawBytes"])))
        ]
        tlogs = root.get("tlogs") or []
        ctlogs = root.get("ctlogs") or []
        entries = (bundle.get("verificationMaterial") or {}).get("tlogEntries") or []
        try:
            scts = list(
                leaf.extensions.get_extension_for_class(
                    x509.PrecertificateSignedCertificateTimestamps
                ).value
            )
        except x509.ExtensionNotFound:
            scts = []
    except Exception as exc:
        return UNVERIFIABLE, f"cannot read the trust root's validity windows: {type(exc).__name__}"

    if not issuers:
        return INVALID, "no certificate authority in the trust root issued the signing certificate"
    if not any(_inside(_window(ca), times) for ca in issuers):
        return INVALID, f"signed at {when}, outside the issuing certificate authority's validity"

    for entry in entries:
        logged = _key_id(entry)
        matching = [t for t in tlogs if _key_id(t) == logged]
        if not matching:
            return INVALID, "a transparency log entry comes from a log not in the trust root"
        if not any(_inside(_window(t), times) for t in matching):
            return INVALID, f"signed at {when}, outside the transparency log key's validity"

    for sct in scts:
        stamp = sct.timestamp if sct.timestamp.tzinfo else sct.timestamp.replace(tzinfo=UTC)
        matching = [c for c in ctlogs if _key_id(c) == sct.log_id]
        if not matching:
            return INVALID, "the certificate's SCT comes from a CT log not in the trust root"
        if not any(_inside(_window(c), [stamp]) for c in matching):
            return INVALID, f"SCT at {_fmt([stamp])}, outside the CT log key's validity"
    return OK, ""


def _issued_by(leaf: Any, ca_cert: Any) -> bool:
    try:
        leaf.verify_directly_issued_by(ca_cert)
    except Exception:
        return False
    return True
