"""Static checks for MCP tool lists and skill files.

This does not proxy a live server. It compares descriptions and hashes the
operator already fetched. A hash pin that still matches is not a promise the
tool is safe.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

_POISON = (
    "ignore previous",
    "ignore all previous",
    "always call",
    "system prompt",
    "do not tell the user",
    "exfiltrate",
)
POISON_PHRASES = _POISON


def tool_fingerprint(tool: dict[str, Any]) -> str:
    body = {
        "name": str(tool.get("name") or ""),
        "description": str(tool.get("description") or ""),
        "inputSchema": tool.get("inputSchema") or tool.get("parameters") or {},
    }
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _folded(name: str) -> str:
    return unicodedata.normalize("NFKC", name).casefold()


def scan_tools(tools: list[dict[str, Any]], pins: dict[str, str] | None = None) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: dict[str, str] = {}
    pins = pins or {}
    for tool in tools:
        name = str(tool.get("name") or "")
        description = str(tool.get("description") or "")
        folded = _folded(name)
        if folded in seen:
            findings.append(
                {
                    "kind": "shadowing",
                    "name": name,
                    "summary": f"{name} folds to the same name as {seen[folded]}",
                }
            )
        elif name:
            seen[folded] = name
        lowered = description.casefold()
        for phrase in _POISON:
            if phrase in lowered:
                findings.append(
                    {
                        "kind": "poisoning",
                        "name": name,
                        "summary": f"description contains {phrase!r}",
                    }
                )
                break
        digest = tool_fingerprint(tool)
        pinned = pins.get(name)
        if pinned is None:
            findings.append({"kind": "unpinned", "name": name, "summary": f"no hash pin for {name}", "sha256": digest})
        elif pinned != digest:
            findings.append(
                {
                    "kind": "rug-pull",
                    "name": name,
                    "summary": f"hash changed for {name}",
                    "sha256": digest,
                    "pinned": pinned,
                }
            )
    return findings


def scan_skills(root: str | Path, pins: dict[str, str]) -> list[dict[str, str]]:
    base = Path(root)
    findings: list[dict[str, str]] = []
    found: dict[str, str] = {}
    if base.is_dir():
        for path in sorted(item for item in base.rglob("*") if item.is_file()):
            rel = path.relative_to(base).as_posix()
            found[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    for rel, digest in found.items():
        pinned = pins.get(rel)
        if pinned is None:
            findings.append({"kind": "unpinned", "name": rel, "summary": f"no hash pin for {rel}", "sha256": digest})
        elif pinned != digest:
            findings.append({"kind": "rug-pull", "name": rel, "summary": f"skill hash changed for {rel}", "sha256": digest})
    for rel in pins:
        if rel not in found:
            findings.append({"kind": "missing", "name": rel, "summary": f"pinned skill {rel} is missing"})
    return findings
