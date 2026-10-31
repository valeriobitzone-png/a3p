import json
import subprocess
import sys
from pathlib import Path


def test_verify_cli_accepts_and_rejects(tmp_path: Path):
    from a3p.ledger import LedgerWriter

    writer = LedgerWriter(tmp_path)
    writer.append("run_start", {"run_id": "cli"})
    sealed = writer.seal()
    ok = subprocess.run(
        [
            sys.executable,
            "-m",
            "a3p",
            "verify",
            str(sealed.path),
            "--public-key",
            str(sealed.public_key_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert ok.returncode == 0, ok.stderr
    assert "OK" in ok.stdout

    lines = sealed.path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["payload"]["run_id"] = "changed"
    lines[0] = json.dumps(record)
    bad = tmp_path / "bad.jsonl"
    bad.write_text("\n".join(lines) + "\n", encoding="utf-8")
    failed = subprocess.run(
        [sys.executable, "-m", "a3p", "verify", str(bad), "--public-key", str(sealed.public_key_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert failed.returncode == 1
    assert "FAIL" in failed.stderr
