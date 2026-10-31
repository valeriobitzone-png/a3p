#!/usr/bin/env python3
"""Print, and optionally start, an Ollama container with no published host port.

``--run`` talks to the local Docker daemon. Unit tests must not pass it.
Access is a unix socket plus a per-run bearer token. The token is a mode-0600
file in the socket directory. ``docker inspect`` shows that directory, not the token.
"""

from __future__ import annotations

import argparse
import secrets
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from a3p.ollama_isolation import commands, limits  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan a network-isolated Ollama container for A3P.")
    parser.add_argument("--sock-dir", type=Path, default=Path.cwd() / "out" / "ollama-sock")
    parser.add_argument("--token", default="", help="per-run bearer token; generated when omitted")
    parser.add_argument("--run", action="store_true", help="execute the docker commands")
    args = parser.parse_args(argv)
    token = args.token or secrets.token_hex(16)
    directory = args.sock_dir if args.sock_dir.is_absolute() else Path.cwd() / args.sock_dir
    planned = commands(directory, token)
    for cmd in planned:
        print(" ".join(cmd))
    print(limits())
    print(f"socket {directory / 'ollama.sock'}")
    print(f"token file {directory / 'token'} mode 0600")
    print("docker inspect lists the socket directory. It does not list the token.")
    if not args.run:
        return 0
    directory.mkdir(parents=True, exist_ok=True)
    for cmd in planned:
        proc = subprocess.run(cmd, check=False)
        if proc.returncode != 0:
            print(f"command failed ({proc.returncode}): {' '.join(cmd)}", file=sys.stderr)
            return proc.returncode
    print("Set A3P_OLLAMA_ISOLATION=container and send requests to the unix socket with the bearer token.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
