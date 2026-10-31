"""Unix-socket to loopback TCP bridge for a sandboxed MCP server.

The sandbox has no IP route. Loopback inside that sandbox still exists, so a
server that only binds ``127.0.0.1`` can be reached by a process in the same
network namespace. This module listens on a unix socket (bind-mounted to the
host) and copies bytes to that loopback port. It does not dial any other
address.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import threading
import time


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bridge a unix socket to a loopback TCP port")
    parser.add_argument("--listen", required=True)
    parser.add_argument("--target", required=True, help="127.0.0.1:port inside this sandbox")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("mcp bridge needs a command", file=sys.stderr)
        return 2
    host, port = _target(args.target)
    if os.path.exists(args.listen):
        os.remove(args.listen)
    child = subprocess.Popen(command)  # noqa: S603
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(args.listen)
        os.chmod(args.listen, 0o600)
        server.listen(8)
        server.settimeout(0.5)
        while child.poll() is None:
            try:
                client, _addr = server.accept()
            except TimeoutError:
                continue
            threading.Thread(target=_handle, args=(client, host, port), daemon=True).start()
    finally:
        server.close()
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
    return int(child.returncode or 0)


def _target(value: str) -> tuple[str, int]:
    host, sep, raw = value.rpartition(":")
    if sep != ":" or host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("bridge target must be 127.0.0.1:port or localhost:port")
    try:
        port = int(raw)
    except ValueError as exc:
        raise SystemExit("bridge port is not an integer") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("bridge port out of range")
    return host, port


def _handle(client: socket.socket, host: str, port: int) -> None:
    try:
        remote = _connect(host, port)
    except OSError:
        client.close()
        return
    left = threading.Thread(target=_pump, args=(client, remote), daemon=True)
    right = threading.Thread(target=_pump, args=(remote, client), daemon=True)
    left.start()
    right.start()
    left.join()
    right.join()
    client.close()
    remote.close()


def _connect(host: str, port: int) -> socket.socket:
    deadline = time.time() + 20
    last: Exception | None = None
    while time.time() < deadline:
        try:
            return socket.create_connection((host, port), timeout=2)
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise OSError(f"loopback {host}:{port} did not accept") from last


def _pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        return
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            return


if __name__ == "__main__":
    raise SystemExit(main())
