"""Read files under a root. Paths outside that root are refused."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from a3p.world.base import Observation


class FilesystemVerifier:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.name = "filesystem"

    def read(self, query: dict[str, Any]) -> Observation:
        raw = str(query.get("path") or "")
        if not raw or raw.startswith("/") or ".." in Path(raw).parts:
            return Observation(self.name, False, "path must stay inside the root", {"path": raw})
        target = (self.root / raw).resolve()
        try:
            target.relative_to(self.root)
        except ValueError:
            return Observation(self.name, False, "path escapes the root", {"path": raw})
        if not target.is_file():
            return Observation(self.name, False, "file is missing", {"path": raw})
        data = target.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        expect = str(query.get("sha256") or "")
        contains = query.get("contains")
        ok = True
        summary = f"sha256 {digest[:12]}"
        if expect and expect != digest:
            ok = False
            summary = "sha256 does not match the pin"
        if isinstance(contains, str) and contains.encode("utf-8") not in data:
            ok = False
            summary = "expected text is not in the file"
        return Observation(self.name, ok, summary, {"path": raw, "sha256": digest, "size": len(data)})
