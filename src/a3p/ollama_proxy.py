"""Per-run bearer proxy in front of Ollama.

Listens on a unix socket. Forwards to the upstream only when the request
carries the matching bearer token. The token is not forwarded. A caller who
does not have the token gets 401. The container reads the token from
``A3P_OLLAMA_TOKEN_FILE`` so ``docker inspect`` does not list the secret.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
from collections.abc import Mapping
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


def load_token(env: Mapping[str, str] | None = None) -> str:
    """Token from a file when ``A3P_OLLAMA_TOKEN_FILE`` is set, else the env value."""
    source = env if env is not None else os.environ
    file_name = source.get("A3P_OLLAMA_TOKEN_FILE") or ""
    if file_name:
        return Path(file_name).read_text(encoding="utf-8").strip()
    return source.get("A3P_OLLAMA_TOKEN") or ""


def main() -> None:
    token = load_token()
    upstream = os.environ.get("A3P_OLLAMA_UPSTREAM") or ""
    path = os.environ.get("A3P_OLLAMA_SOCK") or ""
    if len(token) < 16 or not path or not upstream:
        raise SystemExit("A3P_OLLAMA_TOKEN_FILE or A3P_OLLAMA_TOKEN, plus upstream and socket, are required")
    server = serve(path, upstream, token)
    server.serve_forever()


def serve(path: str, upstream: str, token: str) -> ThreadingHTTPServer:
    if len(token) < 16:
        raise ValueError("token must be at least 16 characters")
    parts = urlsplit(upstream)
    if parts.scheme not in {"http", ""} or not parts.hostname:
        raise ValueError("upstream must be an http URL")
    host = parts.hostname
    port = parts.port or 80
    prefix = parts.path.rstrip("/")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization") or ""
            return _same(header, f"Bearer {token}")

        def _forward(self) -> None:
            if not self._authorized():
                self.send_error(401)
                return
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length) if length else b""
            connection = HTTPConnection(host, port, timeout=10)
            target = prefix + self.path
            headers = {key: value for key, value in self.headers.items() if key.lower() not in {"authorization", "host"}}
            connection.request(self.command, target, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read()
            self.send_response(response.status)
            self.send_header("Content-Type", response.getheader("Content-Type") or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            connection.close()

        def do_GET(self) -> None:
            self._forward()

        def do_POST(self) -> None:
            self._forward()

    if os.path.exists(path):
        os.remove(path)
    server = _UnixServer(path, Handler)
    os.chmod(path, 0o600)
    return server


def _same(left: str, right: str) -> bool:
    return hmac.compare_digest(hashlib.sha256(left.encode("utf-8")).digest(), hashlib.sha256(right.encode("utf-8")).digest())


class _UnixServer(ThreadingHTTPServer):
    def __init__(self, path: str, handler: type[BaseHTTPRequestHandler]) -> None:
        self.address_family = socket.AF_UNIX
        super().__init__(path, handler)  # type: ignore[arg-type]

    def server_bind(self) -> None:
        self.socket = socket.socket(self.address_family, socket.SOCK_STREAM)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()


if __name__ == "__main__":
    main()
