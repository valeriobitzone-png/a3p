"""Block a success claim that no independent world read has verified.

A tool receipt that merely looks successful is not ``world_verified``.
The HTTP server and the MCP-style ``tools/call`` both use :func:`guard_text`.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from a3p.claims import claims_done

REFUSAL = "Blocked: the reply claims success without a probe-verified world read."


def guard_text(text: str, tool_results: list[Any] | None = None) -> tuple[bool, str]:
    """Return ``(allow, text)``. A blocked claim is replaced with a refusal."""
    results = list(tool_results or [])
    if not claims_done(text or ""):
        return True, text
    if any(isinstance(item, dict) and item.get("world_verified") is True for item in results):
        return True, text
    return False, REFUSAL


class GuardServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8766) -> None:
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("guard binds to loopback only")
        self.host = host
        self.port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> str:
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    payload = json.loads(raw.decode("utf-8") or "{}")
                except json.JSONDecodeError:
                    self._send(400, {"error": "invalid json"})
                    return
                if not isinstance(payload, dict):
                    self._send(400, {"error": "expected an object"})
                    return
                if self.path.startswith("/mcp"):
                    self._send(200, _mcp(payload))
                    return
                text = str(payload.get("text") or "")
                tools = payload.get("tool_results")
                allow, shown = guard_text(text, tools if isinstance(tools, list) else [])
                self._send(200, {"allow": allow, "text": shown})

            def _send(self, status: int, body: dict[str, Any]) -> None:
                encoded = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, fmt: str, *args: object) -> None:
                del fmt, args

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self._httpd.daemon_threads = True
        self.port = int(self._httpd.server_address[1])
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="a3p-guard", daemon=True)
        self._thread.start()
        return f"http://{self.host}:{self.port}"

    def serve_forever(self) -> None:
        if self._thread is None:
            self.start()
        if self._thread is not None:
            self._thread.join()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        self._thread = None


def _mcp(payload: dict[str, Any]) -> dict[str, Any]:
    method = str(payload.get("method") or "")
    request_id = payload.get("id")
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "screen",
                        "description": "Block a success claim that has no world_verified tool result.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "text": {"type": "string"},
                                "tool_results": {"type": "array"},
                            },
                        },
                    }
                ]
            },
        }
    if method == "tools/call":
        raw_params = payload.get("params")
        params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
        raw_arguments = params.get("arguments")
        arguments: dict[str, Any] = raw_arguments if isinstance(raw_arguments, dict) else {}
        text = str(arguments.get("text") or "")
        tools = arguments.get("tool_results")
        allow, shown = guard_text(text, tools if isinstance(tools, list) else [])
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": shown}],
                "isError": not allow,
            },
        }
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}}
