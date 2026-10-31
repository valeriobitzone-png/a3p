import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a3p.ledger import LedgerWriter, body_hash, verify_ledger


def _write(tmp_path: Path) -> tuple[Path, str]:
    writer = LedgerWriter(tmp_path)
    writer.append("run_start", {"run_id": "abc"})
    writer.append("scenario", {"scenario_id": "phantom-tool-structured-ok", "passed": False})
    sealed = writer.seal()
    return sealed.path, sealed.public_key_hex


def test_sealed_ledger_verifies(tmp_path: Path):
    path, public = _write(tmp_path)
    result = verify_ledger(path, public)
    assert result.ok, result.reason
    assert result.records == 3
    assert result.head


def test_tampered_payload_fails(tmp_path: Path):
    path, public = _write(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["payload"]["tampered"] = True
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    bad = tmp_path / "bad.jsonl"
    bad.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify_ledger(bad, public)
    assert not result.ok
    assert "hash mismatch" in result.reason


def test_rehashed_without_signature_fails(tmp_path: Path):
    path, public = _write(tmp_path)
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    lines[1]["payload"]["tampered"] = True
    prev = lines[0]["hash"]
    for record in lines[1:]:
        if record["type"] == "signature":
            break
        record["prev"] = prev
        record["hash"] = body_hash(record["seq"], record["prev"], record["type"], record["payload"])
        prev = record["hash"]
    # The signature still covers the original head.
    dumped = [
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for record in lines
    ]
    bad = tmp_path / "rehash.jsonl"
    bad.write_text("\n".join(dumped) + "\n", encoding="utf-8")
    result = verify_ledger(bad, public)
    assert not result.ok
    assert "signature" in result.reason or "prev" in result.reason or "hash" in result.reason


def test_substitute_key_fails_when_pinned(tmp_path: Path):
    path, public = _write(tmp_path)
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    content_head = lines[-2]["hash"]
    other = Ed25519PrivateKey.generate()
    signature = other.sign(bytes.fromhex(content_head))
    other_pub = other.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    lines[-1]["payload"] = {
        "algorithm": "Ed25519",
        "public_key_hex": other_pub,
        "signed_hash": content_head,
        "signature_hex": signature.hex(),
    }
    lines[-1]["hash"] = body_hash(
        lines[-1]["seq"], lines[-1]["prev"], lines[-1]["type"], lines[-1]["payload"]
    )
    bad = tmp_path / "resigned.jsonl"
    bad.write_text(
        "\n".join(json.dumps(record, sort_keys=True, separators=(",", ":")) for record in lines) + "\n",
        encoding="utf-8",
    )
    unpinned = verify_ledger(bad)
    assert unpinned.ok
    pinned = verify_ledger(bad, public)
    assert not pinned.ok
    assert "pinned" in pinned.reason
