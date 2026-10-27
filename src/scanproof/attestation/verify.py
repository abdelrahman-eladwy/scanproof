"""Verify Sigstore bundles. Never raises on bad input: every outcome is an AttestationEvidence.

Cryptography is delegated to sigstore-python (`pip install "scanproof[attestations]"`):
Fulcio certificate chain, signing time from the transparency log or a signed timestamp,
Rekor inclusion, and the DSSE (or message) signature. Identity is *not* checked here; the
claims are extracted from the verified certificate and the policy engine compares them.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from scanproof.attestation.models import (
    AttestationEvidence,
    AttestationStatus,
    SignerClaims,
    Subject,
)

INSTALL_HINT = 'install the extra: pip install "scanproof[attestations]"'
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_BUNDLES = 50
IN_TOTO_PAYLOAD = "application/vnd.in-toto+json"
STATEMENT_TYPES = {"https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1"}
# Pseudo predicate for bundles that sign the artifact bytes directly (`sigstore sign`,
# `cosign sign-blob --bundle`): there is no in-toto statement, the subject is the artifact.
MESSAGE_SIGNATURE = "https://scanproof.dev/sigstore/message-signature"

# Fulcio OIDC extensions, https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
_FULCIO = "1.3.6.1.4.1.57264.1."
_V2_CLAIMS = {
    "8": "issuer",
    "9": "build_signer_uri",
    "10": "build_signer_digest",
    "11": "runner_environment",
    "12": "source_repository_uri",
    "13": "source_repository_digest",
    "14": "source_repository_ref",
    "18": "build_config_uri",
    "21": "run_invocation_uri",
}
_V1_ISSUER = "1"  # deprecated raw-string issuer, used only when the v2 one is absent


class BundleFormatError(ValueError):
    """The input is not a bundle, a JSON-lines file of bundles, or a GitHub attestations reply."""


def split_bundles(raw: bytes) -> list[bytes]:
    """One Sigstore bundle, JSON lines of bundles, or GitHub's `/attestations/{digest}` reply."""
    if len(raw) > MAX_BUNDLE_BYTES:
        raise BundleFormatError(f"bundle input is {len(raw)} bytes; limit is {MAX_BUNDLE_BYTES}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise BundleFormatError("bundle input is not UTF-8 JSON") from None
    try:
        docs: list[Any] = [json.loads(text)]
    except (json.JSONDecodeError, RecursionError):
        try:
            docs = [json.loads(line) for line in text.splitlines() if line.strip()]
        except (json.JSONDecodeError, RecursionError):
            raise BundleFormatError("not JSON or JSON lines") from None
    out: list[bytes] = []
    for doc in docs:
        if isinstance(doc, dict) and isinstance(doc.get("attestations"), list):
            for item in doc["attestations"]:
                bundle = item.get("bundle") if isinstance(item, dict) else None
                if isinstance(bundle, dict):
                    out.append(json.dumps(bundle).encode())
        elif isinstance(doc, dict) and str(doc.get("mediaType", "")).startswith(
            "application/vnd.dev.sigstore.bundle"
        ):
            out.append(json.dumps(doc).encode())
        else:
            raise BundleFormatError("JSON is neither a Sigstore bundle nor an attestations list")
    if len(out) > MAX_BUNDLES:
        raise BundleFormatError(f"{len(out)} bundles; at most {MAX_BUNDLES} are checked")
    return out


class TrustConfig:
    """Which Sigstore instances to trust.

    Default: Sigstore public-good, refreshed over TUF (`offline=True` uses the copy shipped with
    sigstore-python). `trusted_roots`: trusted_root.json files, or JSON lines of them as written
    by `gh attestation trusted-root` (needed for GitHub's own instance, used by private repos).
    A bundle is valid if it verifies against any one of them.
    """

    def __init__(self, trusted_roots: list[Path] | None = None, *, offline: bool = False) -> None:
        self.trusted_roots = list(trusted_roots or [])
        self.offline = offline
        self._verifiers: list[Any] | None = None
        self._error: str | None = None

    def verifiers(self) -> list[Any]:
        """Built once. Raises RuntimeError with a readable reason if trust can't be set up."""
        if self._verifiers is None and self._error is None:
            try:
                self._verifiers = self._build()
            except ImportError:
                self._error = f"sigstore is not installed ({INSTALL_HINT})"
            except Exception as exc:  # TUF / file / format errors: all mean "cannot verify"
                self._error = f"cannot load the Sigstore trust root: {type(exc).__name__}: {exc}"
        if self._error:
            raise RuntimeError(self._error)
        return self._verifiers or []

    def _build(self) -> list[Any]:
        from sigstore.models import ClientTrustConfig, TrustedRoot
        from sigstore.verify import Verifier

        if not self.trusted_roots:
            config = ClientTrustConfig.production(offline=self.offline)
            return [Verifier(trusted_root=config.trusted_root)]
        verifiers = []
        with tempfile.TemporaryDirectory() as tmp:
            for path in self.trusted_roots:
                text = path.read_text(encoding="utf-8").strip()
                try:
                    json.loads(text)
                    docs = [text]
                except json.JSONDecodeError:
                    docs = [line for line in text.splitlines() if line.strip()]
                for i, doc in enumerate(docs):
                    one = Path(tmp) / f"{len(verifiers)}-{i}.json"
                    one.write_text(doc, encoding="utf-8")
                    verifiers.append(Verifier(trusted_root=TrustedRoot.from_file(str(one))))
        if not verifiers:
            raise ValueError("no trusted roots in the given files")
        return verifiers


class _IdentityCheckedByPolicy:
    """sigstore requires an identity policy; ScanProof's policy engine checks identity instead,
    against claims taken from the certificate this verification just validated."""

    def verify(self, cert: Any) -> None:
        return None


def verify_bundle(
    raw: bytes,
    trust: TrustConfig,
    *,
    origin: str | None = None,
    artifact_sha256: str | None = None,
) -> AttestationEvidence:
    """Verify one bundle. `artifact_sha256` (hex) is needed only for message-signature bundles,
    which sign the artifact itself rather than an in-toto statement about it."""
    sha = hashlib.sha256(raw).hexdigest()

    def fail(status: AttestationStatus, reason: str) -> AttestationEvidence:
        return AttestationEvidence(status=status, reason=reason, origin=origin, bundle_sha256=sha)

    try:
        verifiers = trust.verifiers()
    except RuntimeError as exc:
        return fail(AttestationStatus.UNVERIFIABLE, str(exc))
    try:
        from sigstore.models import Bundle

        bundle = Bundle.from_json(raw)
    except ImportError:
        return fail(AttestationStatus.UNVERIFIABLE, f"sigstore is not installed ({INSTALL_HINT})")
    except Exception as exc:
        return fail(AttestationStatus.INVALID, f"not a valid Sigstore bundle: {_short(exc)}")

    try:  # building the envelope validates it, and can raise (found by fuzzing)
        is_dsse = bundle._dsse_envelope is not None
    except Exception as exc:
        return fail(AttestationStatus.INVALID, f"malformed DSSE envelope: {_short(exc)}")
    if not is_dsse and not artifact_sha256:
        return fail(
            AttestationStatus.UNVERIFIABLE,
            "message-signature bundle, but the signed artifact is not available",
        )

    errors: list[str] = []
    for verifier in verifiers:
        try:
            if is_dsse:
                payload_type, payload = verifier.verify_dsse(bundle, _IdentityCheckedByPolicy())
            else:
                verifier.verify_artifact(
                    _prehashed(artifact_sha256 or ""), bundle, _IdentityCheckedByPolicy()
                )
                payload_type, payload = None, None
            break
        except Exception as exc:  # VerificationError and anything malformed inside the bundle
            errors.append(_short(exc))
    else:
        return fail(
            AttestationStatus.INVALID,
            "signature verification failed: " + "; ".join(dict.fromkeys(errors)),
        )

    # ---- verified: everything below comes from authenticated data
    try:
        signer = signer_claims(bundle.signing_certificate)
    except Exception as exc:
        return fail(AttestationStatus.INVALID, f"unreadable signing certificate: {_short(exc)}")

    if payload is None:  # message signature over the artifact bytes
        return AttestationEvidence(
            status=AttestationStatus.VERIFIED,
            origin=origin,
            bundle_sha256=sha,
            predicate_type=MESSAGE_SIGNATURE,
            subjects=[Subject(digest={"sha256": (artifact_sha256 or "").lower()})],
            signer=signer,
        )

    if payload_type != IN_TOTO_PAYLOAD:
        return fail(AttestationStatus.INVALID, f"DSSE payload type {payload_type!r} is not in-toto")
    try:
        statement = json.loads(payload)
    except (ValueError, RecursionError):
        return fail(AttestationStatus.INVALID, "in-toto statement is not JSON")
    parsed = _parse_statement(statement)
    if isinstance(parsed, str):
        return fail(AttestationStatus.INVALID, parsed)
    statement_type, predicate_type, subjects = parsed
    return AttestationEvidence(
        status=AttestationStatus.VERIFIED,
        origin=origin,
        bundle_sha256=sha,
        statement_type=statement_type,
        predicate_type=predicate_type,
        subjects=subjects,
        signer=signer,
        predicate_summary=_summarize(predicate_type, statement.get("predicate")),
    )


def verify_bundles(
    raw: bytes,
    trust: TrustConfig,
    *,
    origin: str | None = None,
    artifact_sha256: str | None = None,
) -> list[AttestationEvidence]:
    try:
        bundles = split_bundles(raw)
    except BundleFormatError as exc:
        return [
            AttestationEvidence(
                status=AttestationStatus.INVALID,
                reason=str(exc),
                origin=origin,
                bundle_sha256=hashlib.sha256(raw).hexdigest(),
            )
        ]
    return [
        verify_bundle(b, trust, origin=origin, artifact_sha256=artifact_sha256) for b in bundles
    ]


# ---------------------------------------------------------------- helpers


def _prehashed(hex_digest: str) -> Any:
    from sigstore.hashes import Hashed
    from sigstore_models.common.v1 import HashAlgorithm

    return Hashed(algorithm=HashAlgorithm.SHA2_256, digest=bytes.fromhex(hex_digest))


def _parse_statement(doc: Any) -> tuple[str, str, list[Subject]] | str:
    if not isinstance(doc, dict):
        return "in-toto statement is not an object"
    stype = doc.get("_type")
    if stype not in STATEMENT_TYPES:
        return f"unsupported statement type {stype!r}"
    ptype = doc.get("predicateType")
    if not isinstance(ptype, str) or not ptype:
        return "statement has no predicateType"
    raw_subjects = doc.get("subject")
    if not isinstance(raw_subjects, list) or not raw_subjects:
        return "statement has no subjects"
    subjects = []
    for s in raw_subjects:
        if not isinstance(s, dict) or not isinstance(s.get("digest"), dict):
            return "statement subject without a digest"
        digest = {str(k).lower(): str(v).lower() for k, v in s["digest"].items()}
        name = s.get("name")
        subjects.append(Subject(name=name if isinstance(name, str) else None, digest=digest))
    return stype, ptype, subjects


def _summarize(predicate_type: str, predicate: Any) -> dict[str, str]:
    """A few fields worth showing in a report. Informational: never used to decide."""
    if not isinstance(predicate, dict):
        return {}
    pick: dict[str, Callable[[dict], Any]] = {}
    if predicate_type.startswith("https://slsa.dev/provenance/v1"):
        pick = {
            "build_type": lambda p: p["buildDefinition"]["buildType"],
            "builder_id": lambda p: p["runDetails"]["builder"]["id"],
            "invocation_id": lambda p: p["runDetails"]["metadata"]["invocationId"],
        }
    elif predicate_type == "https://cosign.sigstore.dev/attestation/vuln/v1":
        pick = {
            "scanner_uri": lambda p: p["scanner"]["uri"],
            "scanner_version": lambda p: p["scanner"]["version"],
            "scan_finished_on": lambda p: p["metadata"]["scanFinishedOn"],
            "invocation_uri": lambda p: p["invocation"]["uri"],
        }
    out = {}
    for key, get in pick.items():
        try:
            value = get(predicate)
        except (KeyError, TypeError):
            continue
        if isinstance(value, str | int | float):
            out[key] = str(value)[:300]
    return out


def signer_claims(cert: Any) -> SignerClaims:
    from cryptography import x509

    values: dict[str, str] = {}
    v1_issuer = None
    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        if not oid.startswith(_FULCIO):
            continue
        tail = oid[len(_FULCIO) :]
        raw = getattr(ext.value, "value", None)
        if not isinstance(raw, bytes):
            continue
        if tail in _V2_CLAIMS:
            text = _der_utf8(raw)
            if text is not None:
                values[_V2_CLAIMS[tail]] = text
        elif tail == _V1_ISSUER:
            v1_issuer = raw.decode("utf-8", "replace")
    if "issuer" not in values and v1_issuer:
        values["issuer"] = v1_issuer
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san = [*san_ext.get_values_for_type(x509.UniformResourceIdentifier)]
        san += san_ext.get_values_for_type(x509.RFC822Name)
    except x509.ExtensionNotFound:
        san = []
    return SignerClaims(**values, san=san)


def _der_utf8(raw: bytes) -> str | None:
    """Decode a DER UTF8String (tag 0x0C), as Fulcio v2 extensions are encoded."""
    if len(raw) < 2 or raw[0] != 0x0C:
        return None
    length, offset = raw[1], 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or len(raw) < 2 + n:
            return None
        length, offset = int.from_bytes(raw[2 : 2 + n], "big"), 2 + n
    if len(raw) != offset + length:
        return None
    try:
        return raw[offset:].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _short(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}".replace("\n", " ")
    return text if len(text) <= 300 else text[:297] + "..."
