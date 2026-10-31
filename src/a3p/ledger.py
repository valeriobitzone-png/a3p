"""Append-only JSONL evidence ledger with a hash chain and an Ed25519 seal.

Verification uses the public key. It does not need the private key, the
probe, or the original agent. `verify --public-key` pins the auditor's key
so a rewritten chain with a substitute key does not pass.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from a3p.keys import load_private

GENESIS = "0" * 64


@dataclass
class VerifyResult:
    ok: bool
    reason: str
    records: int = 0
    head: str = ""
    public_key_hex: str = ""


@dataclass
class SealedLedger:
    path: Path
    private_key_path: Path
    public_key_path: Path
    head: str
    public_key_hex: str


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def body_hash(seq: int, prev: str, typ: str, payload: dict) -> str:
    raw = canonical({"seq": seq, "prev": prev, "type": typ, "payload": payload})
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class LedgerWriter:
    def __init__(
        self,
        directory: Path,
        *,
        signing_key: Ed25519PrivateKey | None = None,
        private_key_path: Path | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "ledger.jsonl"
        self.public_key_path = self.directory / "auditor.pub"
        self._seq = 0
        self._prev = GENESIS
        self._lines: list[str] = []
        if signing_key is None:
            signing_key, stored = load_private()
            private_key_path = stored
        self._key = signing_key
        self.signing_key = signing_key
        self.private_key_path = Path(private_key_path) if private_key_path else Path()
        self.public_key_hex = self._key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()

    def append(self, typ: str, payload: dict) -> str:
        digest = body_hash(self._seq, self._prev, typ, payload)
        record = {
            "seq": self._seq,
            "prev": self._prev,
            "type": typ,
            "payload": payload,
            "hash": digest,
        }
        self._lines.append(canonical(record))
        self._prev = digest
        self._seq += 1
        return digest

    def seal(self) -> SealedLedger:
        signed = self._prev
        signature = self._key.sign(bytes.fromhex(signed))
        self.append(
            "signature",
            {
                "algorithm": "Ed25519",
                "public_key_hex": self.public_key_hex,
                "signed_hash": signed,
                "signature_hex": signature.hex(),
            },
        )
        self.path.write_text("\n".join(self._lines) + "\n", encoding="utf-8")
        # The private key stays in the key store. The report directory gets the public key only.
        self.public_key_path.write_text(self.public_key_hex + "\n", encoding="utf-8")
        leaked = self.directory / "auditor.pem"
        if leaked.exists():
            leaked.unlink()
        return SealedLedger(
            path=self.path,
            private_key_path=self.private_key_path,
            public_key_path=self.public_key_path,
            head=signed,
            public_key_hex=self.public_key_hex,
        )


def verify_ledger(path: str | Path, public_key_hex: str | None = None) -> VerifyResult:
    file = Path(path)
    if not file.is_file():
        return VerifyResult(False, f"ledger not found: {file}")
    text = file.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return VerifyResult(False, "ledger is empty")
    prev = GENESIS
    parsed: list[dict] = []
    for index, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return VerifyResult(False, f"line {index} is not JSON", records=index)
        for field in ("seq", "prev", "type", "payload", "hash"):
            if field not in record:
                return VerifyResult(False, f"seq {record.get('seq', index)} missing {field}")
        if record["seq"] != index:
            return VerifyResult(False, f"expected seq {index}, found {record['seq']}")
        if record["prev"] != prev:
            return VerifyResult(False, f"prev mismatch at seq {index}")
        digest = body_hash(record["seq"], record["prev"], record["type"], record["payload"])
        if digest != record["hash"]:
            return VerifyResult(False, f"hash mismatch at seq {index}", records=index + 1)
        prev = digest
        parsed.append(record)
    last = parsed[-1]
    if last["type"] != "signature":
        return VerifyResult(False, "ledger is not sealed with a signature record", records=len(parsed))
    payload = last["payload"]
    if len(parsed) < 2:
        return VerifyResult(False, "signature does not cover any probe record", records=len(parsed))
    content_head = parsed[-2]["hash"]
    if payload.get("signed_hash") != content_head:
        return VerifyResult(False, "signature does not cover the last probe record", records=len(parsed))
    if payload.get("algorithm") != "Ed25519":
        return VerifyResult(False, "unsupported signature algorithm", records=len(parsed))
    embedded = str(payload.get("public_key_hex") or "")
    signature_hex = str(payload.get("signature_hex") or "")
    pinned = (public_key_hex or "").strip().lower()
    if pinned and embedded.lower() != pinned:
        return VerifyResult(
            False,
            "public key does not match the pinned auditor key",
            records=len(parsed),
            head=content_head,
            public_key_hex=embedded,
        )
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(embedded))
        key.verify(bytes.fromhex(signature_hex), bytes.fromhex(content_head))
    except (InvalidSignature, ValueError) as exc:
        return VerifyResult(
            False,
            f"signature rejected ({exc.__class__.__name__})",
            records=len(parsed),
            head=content_head,
            public_key_hex=embedded,
        )
    return VerifyResult(
        True,
        "ok",
        records=len(parsed),
        head=content_head,
        public_key_hex=embedded,
    )


def load_public_key(path: str | Path) -> str:
    text = Path(path).read_text(encoding="utf-8").strip()
    if "BEGIN PUBLIC KEY" in text or "BEGIN PRIVATE KEY" in text:
        key = serialization.load_pem_public_key(text.encode("utf-8")) if "PUBLIC" in text else None
        if key is None:
            private = serialization.load_pem_private_key(text.encode("utf-8"), password=None)
            raw = private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            return raw.hex()
        return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return text.split()[0]
