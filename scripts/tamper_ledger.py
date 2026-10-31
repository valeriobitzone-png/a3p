"""Flip one payload in a ledger without repairing the hash chain.

Used by `make demo` to show that `a3p verify` rejects a copied file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def tamper(source: Path, dest: Path) -> None:
    lines = [line for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) < 2:
        raise SystemExit("ledger is too short to tamper")
    record = json.loads(lines[1])
    payload = dict(record["payload"])
    payload["tampered"] = True
    record["payload"] = payload
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: tamper_ledger.py SOURCE DEST", file=sys.stderr)
        return 2
    tamper(Path(sys.argv[1]), Path(sys.argv[2]))
    print(sys.argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
