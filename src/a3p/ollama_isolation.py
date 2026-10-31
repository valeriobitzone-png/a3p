"""Plan and attest an Ollama server that is not published on a host port.

The container joins an internal Docker network, so it cannot open outbound
connections of its own. No ``-p`` binding is created. A second container on
that network listens on a unix socket bind-mounted to the host and forwards
to Ollama only when the request carries the per-run bearer token.

The token is a mode-0600 file inside the socket directory, bind-mounted with
that directory. ``docker inspect`` shows the directory path, not the token
bytes. Anyone who can read that file and the socket can connect. Root on the
host can still read the file. This is not a claim that a local root user is
locked out.

Pull a model before moving the server onto the internal network. The proxy
image is the sandbox image, with the host ``/usr`` mounted so Python is
available.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from a3p.isolation import docker_prefix, sandbox_image

IMAGE = "ollama/ollama"
NETWORK = "a3p-ollama"
CONTAINER = "a3p-ollama"
PROXY = "a3p-ollama-proxy"
Runner = Callable[..., subprocess.CompletedProcess[str]]


def commands(sock_dir: Path, token: str) -> list[list[str]]:
    if len(token) < 16 or not token.isalnum():
        raise ValueError("token must be at least 16 alphanumeric characters")
    directory = Path(sock_dir)
    if not directory.is_absolute():
        raise ValueError("socket directory must be absolute")
    directory.mkdir(parents=True, exist_ok=True)
    token_path = directory / "token"
    token_path.write_text(token + "\n", encoding="utf-8")
    token_path.chmod(0o600)
    try:
        directory.chmod(0o700)
    except OSError:
        pass
    src = str(Path(__file__).resolve().parent.parent)
    return [
        ["docker", "network", "create", "--internal", NETWORK],
        [
            "docker", "run", "-d",
            "--name", CONTAINER,
            "--network", NETWORK,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            IMAGE,
        ],
        [
            "docker", "run", "-d",
            "--name", PROXY,
            "--network", NETWORK,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "-v", f"{directory}:/opt/a3p-socks",
            "-v", "/usr:/usr:ro",
            "-v", f"{src}:/opt/a3p-src:ro",
            "-e", "PYTHONPATH=/opt/a3p-src",
            "-e", "A3P_OLLAMA_TOKEN_FILE=/opt/a3p-socks/token",
            "-e", "A3P_OLLAMA_UPSTREAM=http://a3p-ollama:11434",
            "-e", "A3P_OLLAMA_SOCK=/opt/a3p-socks/ollama.sock",
            "--entrypoint", "/usr/bin/python3",
            sandbox_image(),
            "-m", "a3p.ollama_proxy",
        ],
    ]


def limits() -> str:
    return (
        "The Ollama container is on an internal Docker network and publishes no host port. "
        "The probe reaches it through a unix socket and a per-run bearer token. "
        "The token is a mode-0600 file in the socket directory, not a container environment variable. "
        "docker inspect shows that directory path and does not include the token bytes. "
        "A process that can read the file and the socket can still connect. Root on the host can read the file. "
        "Set A3P_OLLAMA_ISOLATION=container only after docker inspect shows a3p-ollama "
        "on the internal network with no host port binding. "
        "The report claims ollama-container only when that inspect succeeds."
    )


def attested(run: Runner | None = None) -> bool:
    """True when docker inspect shows the container on the internal network and no host port."""
    prefix = docker_prefix(run)
    if not prefix:
        return False
    execute = run or subprocess.run
    try:
        proc = execute(
            [*prefix, "inspect", CONTAINER],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0 or not proc.stdout:
        return False
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        return False
    return _matches(data[0])


def _matches(item: dict[str, Any]) -> bool:
    networks = (item.get("NetworkSettings") or {}).get("Networks") or {}
    if not isinstance(networks, dict) or NETWORK not in networks:
        return False
    host_config = item.get("HostConfig") or {}
    bindings = host_config.get("PortBindings") or {}
    if not isinstance(bindings, dict):
        return False
    return bindings == {}
