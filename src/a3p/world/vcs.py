"""Read a local Git checkout or a GitHub commit the operator names."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import httpx

from a3p.world.base import Observation


def _git(root: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    text = (proc.stdout or proc.stderr or "").strip()
    return proc.returncode, text


class GitVerifier:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.name = "git"

    def read(self, query: dict[str, Any]) -> Observation:
        action = str(query.get("action") or "head")
        if action == "head":
            code, head = _git(self.root, "rev-parse", "HEAD")
            expect = str(query.get("sha") or "")
            ok = code == 0 and bool(head) and (not expect or head.startswith(expect))
            summary = head or "git rev-parse failed"
            return Observation(self.name, ok, summary, {"sha": head})
        if action == "clean":
            code, status = _git(self.root, "status", "--porcelain")
            ok = code == 0 and status == ""
            return Observation(self.name, ok, "clean" if ok else "dirty or unreadable", {"status": status})
        if action == "file":
            path = str(query.get("path") or "")
            code, blob = _git(self.root, "hash-object", path)
            expect = str(query.get("sha") or "")
            ok = code == 0 and bool(blob) and (not expect or blob == expect)
            return Observation(self.name, ok, blob or "hash-object failed", {"sha": blob, "path": path})
        return Observation(self.name, False, f"unknown git action {action}", {})


class GitHubVerifier:
    """GET one commit from the GitHub API. The client is the operator's."""

    def __init__(self, repo: str, *, client: httpx.Client | None = None, token: str = "") -> None:
        self.repo = repo.strip("/")
        self.client = client
        self.token = token
        self.name = "github"

    def read(self, query: dict[str, Any]) -> Observation:
        sha = str(query.get("sha") or "")
        if not sha or ".." in self.repo or " " in self.repo:
            return Observation(self.name, False, "repo and sha are required", {})
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        url = f"https://api.github.com/repos/{self.repo}/commits/{sha}"
        try:
            if self.client is not None:
                response = self.client.get(url, headers=headers)
            else:
                response = httpx.get(url, headers=headers, timeout=20.0)
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return Observation(self.name, False, f"{type(exc).__name__}: {exc}", {})
        if not isinstance(body, dict):
            return Observation(self.name, False, "commit response was not an object", {})
        found = str(body.get("sha") or "")
        ok = found.startswith(sha) or sha.startswith(found[:12])
        return Observation(self.name, ok, found or "commit has no sha", {"sha": found})
