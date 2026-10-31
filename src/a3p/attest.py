"""in-toto statements, an Ed25519 DSSE envelope, and optional Sigstore bundles.

Ed25519 DSSE is the offline signature. It is not a Fulcio certificate.
Keyless signing calls sigstore-python (Fulcio and Rekor) only when an ambient
OIDC token is present, which GitHub Actions provides when the job sets
``id-token: write``. Verification uses sigstore's verifier, which checks the
Rekor inclusion proof, and can also run ``sigstore verify identity``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_TYPE = "urn:a3p:probe-result:v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


class AttestationError(Exception):
    pass


class KeylessUnavailable(AttestationError):
    pass


def canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def statement_for(name: str, payload: bytes, predicate: dict[str, Any]) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": hashlib.sha256(payload).hexdigest()}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding, version 1."""

    def part(data: bytes) -> bytes:
        return str(len(data)).encode("ascii") + b" " + data

    return b"DSSEv1 " + part(payload_type.encode("utf-8")) + b" " + part(payload)


def sign_statement(document: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    raw = canonical(document).encode("utf-8")
    signature = key.sign(pae(PAYLOAD_TYPE, raw))
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(raw).decode("ascii"),
        "signatures": [{"keyid": public, "sig": base64.b64encode(signature).decode("ascii")}],
    }


def verify_envelope(envelope: dict[str, Any], public_key_hex: str | None = None) -> dict[str, Any]:
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise AttestationError("payloadType is not an in-toto statement")
    try:
        raw = base64.b64decode(str(envelope.get("payload") or ""), validate=True)
    except (ValueError, TypeError) as exc:
        raise AttestationError("payload is not base64") from exc
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise AttestationError("envelope has no signatures")
    first = signatures[0]
    if not isinstance(first, dict):
        raise AttestationError("signature entry is not an object")
    keyid = str(first.get("keyid") or "")
    pinned = (public_key_hex or keyid).strip().lower()
    if public_key_hex and keyid.lower() != pinned:
        raise AttestationError("signature key does not match the pinned public key")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned))
        key.verify(base64.b64decode(str(first.get("sig") or "")), pae(PAYLOAD_TYPE, raw))
    except (ValueError, InvalidSignature) as exc:
        raise AttestationError(f"signature rejected ({type(exc).__name__})") from exc
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationError("payload is not JSON") from exc
    if not isinstance(document, dict) or document.get("_type") != STATEMENT_TYPE:
        raise AttestationError("payload is not an in-toto Statement v1")
    return document


def ambient_identity() -> Any:
    """Return a sigstore IdentityToken, or raise KeylessUnavailable."""
    try:
        from sigstore.oidc import IdentityToken, detect_credential
    except ImportError as exc:
        raise KeylessUnavailable(
            "The sigstore package is not installed, so Fulcio and Rekor are not called. "
            "Install the sigstore extra. Ed25519 DSSE remains the offline signature."
        ) from exc
    try:
        raw = detect_credential()
    except Exception as exc:
        raise KeylessUnavailable(
            "Ambient OIDC was detected but no token was issued. "
            "GitHub Actions needs permissions.id-token: write. "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if not raw:
        raise KeylessUnavailable(
            "No ambient OIDC token. Fulcio and Rekor were not called. "
            "GitHub Actions provides one when the job sets id-token: write. "
            "Ed25519 DSSE remains the offline signature."
        )
    try:
        return IdentityToken(raw)
    except Exception as exc:
        raise KeylessUnavailable(f"OIDC token was rejected: {type(exc).__name__}: {exc}") from exc


def _production_sign(payload: bytes, identity: Any) -> Any:
    from sigstore.models import ClientTrustConfig
    from sigstore.sign import SigningContext

    config = ClientTrustConfig.production()
    context = SigningContext.from_trust_config(config)
    with context.signer(identity) as signer:
        return signer.sign_artifact(payload)


def sign_keyless(document: dict[str, Any]) -> dict[str, Any]:
    """Sign the canonical statement with Fulcio and record it in Rekor.

    Raises KeylessUnavailable when sigstore is missing or no OIDC token exists.
    A Fulcio or Rekor failure is an AttestationError and is not replaced with
    an Ed25519 signature.
    """
    identity = ambient_identity()
    payload = canonical(document).encode("utf-8")
    try:
        bundle = _production_sign(payload, identity)
        raw_bundle = bundle.to_json()
    except (KeylessUnavailable, AttestationError):
        raise
    except Exception as exc:
        raise AttestationError(f"Fulcio or Rekor refused the signature: {type(exc).__name__}: {exc}") from exc
    try:
        parsed = json.loads(raw_bundle)
    except json.JSONDecodeError as exc:
        raise AttestationError("sigstore bundle was not JSON") from exc
    if not isinstance(parsed, dict):
        raise AttestationError("sigstore bundle was not an object")
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle+json",
        "bundle": parsed,
        "artifactSha256": hashlib.sha256(payload).hexdigest(),
        "identity": str(identity.identity),
        "issuer": str(identity.issuer),
    }


def sign_result(document: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    """Keyless Sigstore when OIDC is available, plus the Ed25519 envelope always."""
    envelope = sign_statement(document, key)
    try:
        bundle = sign_keyless(document)
    except KeylessUnavailable as exc:
        return {"kind": "ed25519-dsse", "envelope": envelope, "keyless": str(exc)}
    return {"kind": "sigstore-bundle", "bundle": bundle, "envelope": envelope}


def verify_keyless(
    document: dict[str, Any],
    bundle_file: dict[str, Any] | str,
    *,
    identity: str,
    issuer: str,
) -> dict[str, str]:
    """Verify a bundle with sigstore, including the Rekor inclusion proof."""
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify.policy import Identity

    payload = canonical(document).encode("utf-8")
    raw = bundle_file if isinstance(bundle_file, str) else json.dumps(_bundle_body(bundle_file))
    try:
        bundle = Bundle.from_json(raw)
    except Exception as exc:
        raise AttestationError(f"bundle was rejected: {type(exc).__name__}: {exc}") from exc
    try:
        Verifier.production().verify_artifact(payload, bundle, Identity(identity=identity, issuer=issuer))
    except Exception as exc:
        raise AttestationError(f"sigstore verify failed: {type(exc).__name__}: {exc}") from exc
    proof = getattr(bundle.log_entry._inner, "inclusion_proof", None)
    checkpoint = getattr(proof, "checkpoint", None)
    if proof is None or not checkpoint:
        raise AttestationError("Rekor inclusion proof is missing")
    return {
        "logIndex": str(bundle.log_entry._inner.log_index),
        "integratedTime": str(bundle.log_entry._inner.integrated_time),
        "identity": identity,
        "issuer": issuer,
    }


def _bundle_body(document: dict[str, Any]) -> dict[str, Any]:
    nested = document.get("bundle")
    if isinstance(nested, dict):
        return nested
    return document


def sigstore_verify_command(artifact: str, bundle: str, identity: str, issuer: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "sigstore",
        "verify",
        "identity",
        "--bundle",
        bundle,
        "--cert-identity",
        identity,
        "--cert-oidc-issuer",
        issuer,
        artifact,
    ]


def verify_keyless_cli(artifact: str, bundle: str, identity: str, issuer: str) -> str:
    """Run ``sigstore verify identity`` and return its stdout."""
    command = sigstore_verify_command(artifact, bundle, identity, issuer)
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as exc:
        raise AttestationError(f"could not run sigstore verify: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "sigstore verify failed").strip()
        raise AttestationError(detail)
    return completed.stdout
