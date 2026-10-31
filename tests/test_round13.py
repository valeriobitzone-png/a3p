"""Isolation preference, Streamable HTTP, token file, dashboard TLS, and a 200-row probe."""

from __future__ import annotations

import json
import socket
import ssl
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from a3p.cli import main
from a3p.dashboard import generate_certificate, serve
from a3p.isolation import best_level, configured_level, runsc_platform
from a3p.mcp_dynamic import (
    McpScanError,
    StreamableSession,
    _sse_payload,
    resolve_sandbox,
    run_live_scan,
)
from a3p.mcp_vulnerable import serve_streamable
from a3p.ollama_proxy import load_token


def test_runsc_ranks_above_docker_and_the_env_can_force_nsjail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "a3p.isolation.shutil.which",
        lambda name: "/usr/bin/runsc" if name == "runsc" else None,
    )
    monkeypatch.setattr("a3p.isolation.docker_prefix", lambda run=None: ["docker"])
    monkeypatch.setattr("a3p.isolation._image_present", lambda run: True)
    assert best_level() == "runsc"
    monkeypatch.setenv("A3P_ISOLATION", "nsjail")
    assert configured_level() == "nsjail"
    assert resolve_sandbox("auto", allow_process=False) == "nsjail"
    monkeypatch.delenv("A3P_RUNSC_PLATFORM", raising=False)
    assert runsc_platform() == "systrap"
    monkeypatch.setenv("A3P_RUNSC_PLATFORM", "kvm")
    assert runsc_platform() == "kvm"
    monkeypatch.setenv("A3P_RUNSC_PLATFORM", "ptrace")
    assert runsc_platform() == "ptrace"
    monkeypatch.setenv("A3P_RUNSC_PLATFORM", "nope")
    assert runsc_platform() == "systrap"


def test_load_token_reads_the_file_before_the_environment(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text("abcdefghijklmnop\n", encoding="utf-8")
    assert load_token({"A3P_OLLAMA_TOKEN_FILE": str(path), "A3P_OLLAMA_TOKEN": "z" * 16}) == "abcdefghijklmnop"
    assert load_token({"A3P_OLLAMA_TOKEN": "z" * 16}) == "z" * 16
    assert load_token({}) == ""


def test_streamable_http_reaches_the_demo() -> None:
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    port = int(holder.getsockname()[1])
    holder.close()
    server = serve_streamable(("127.0.0.1", port), socket.AF_INET)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        denied = httpx.get(f"http://127.0.0.1:{port}/mcp", timeout=5)
        assert denied.status_code == 405
        missing = httpx.get(f"http://127.0.0.1:{port}/nope", timeout=5)
        assert missing.status_code == 404
        bad = httpx.post(f"http://127.0.0.1:{port}/mcp", content=b"not-json", timeout=5)
        assert bad.status_code == 400
        session = StreamableSession(f"http://127.0.0.1:{port}")
        result = session.request(
            "initialize",
            {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}},
        )
        assert result["protocolVersion"] == "2025-03-26"
        session.notify("notifications/initialized")
        listed = session.request("tools/list")
        assert any(item.get("name") == "notes" for item in listed["tools"])
        session.close()
    finally:
        server.shutdown()


def test_streamable_session_parses_sse_and_rejects_a_bad_body() -> None:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            raw = json.loads(self.rfile.read(length).decode("utf-8"))
            method = str(raw.get("method") or "")
            if method == "sse":
                body = b'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n'
                ctype = "text/event-stream"
            elif method == "empty":
                body = b"event: message\n\n"
                ctype = "text/event-stream"
            elif method == "list":
                body = b"[1]"
                ctype = "application/json"
            elif method == "fail":
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"message": "no"}}).encode()
                ctype = "application/json"
            else:
                self.send_error(500)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = int(httpd.server_address[1])
    try:
        session = StreamableSession(f"http://127.0.0.1:{port}")
        assert session.request("sse") == {"ok": True}
        with pytest.raises(McpScanError, match="no data"):
            session.request("empty")
        with pytest.raises(McpScanError, match="not an object"):
            session.request("list")
        with pytest.raises(McpScanError, match="no"):
            session.request("fail")
        with pytest.raises(httpx.HTTPStatusError):
            session.request("down")
        session.close()
    finally:
        httpd.shutdown()
    with pytest.raises(McpScanError, match="not an object"):
        _sse_payload('data: ["nope"]')


def test_streamable_live_scan_records_poisoning(tmp_path: Path) -> None:
    report = run_live_scan(
        level="process",
        transport="streamable",
        output=tmp_path,
        probes=[{"id": "one", "language": "en", "text": "note"}],
        allow_process=True,
    )
    assert report["transport"] == "streamable"
    assert report["sandbox"] == "process"
    assert isinstance(report["elapsed_s"], float)
    assert any(item["kind"] == "poisoning" for item in report["findings"])


def test_streamable_tcp_bridge(tmp_path: Path) -> None:
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    port = int(holder.getsockname()[1])
    holder.close()
    report = run_live_scan(
        level="process",
        transport="streamable",
        output=tmp_path,
        tcp_port=port,
        probes=[{"id": "one", "language": "en", "text": "note"}],
        allow_process=True,
    )
    assert report["tcp_port"] == port
    assert any(item["kind"] == "secret" for item in report["findings"])


def test_dashboard_tls_and_the_cli_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cert, key = generate_certificate(tmp_path, "127.0.0.1")
    generate_certificate(tmp_path / "dns", "dash.example")
    generate_certificate(tmp_path / "ip", "10.1.2.3")
    generate_certificate(tmp_path / "wild", "0.0.0.0")
    generate_certificate(tmp_path / "local", "localhost")
    history = tmp_path / "history"
    history.mkdir()
    server = serve(history, "127.0.0.1", 0, certfile=str(cert), keyfile=str(key))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        context = ssl._create_unverified_context()
        with urllib.request.urlopen(f"https://127.0.0.1:{server.server_address[1]}/", context=context) as response:
            body = response.read().decode("utf-8")
        assert response.status == 200
        assert "A3P run history" in body
    finally:
        server.shutdown()
    with pytest.raises(ValueError, match="both"):
        serve(history, certfile=str(cert))
    assert main(["dashboard", "--history", str(history), "--tls"]) == 2
    assert main([
        "dashboard", "--history", str(history), "--allow-remote", "--token", "a" * 16,
        "--tls-cert", str(cert),
    ]) == 2

    seen: dict[str, str | None] = {}

    def fake_serve(*args: object, **kwargs: object) -> object:
        seen["certfile"] = str(kwargs.get("certfile"))
        seen["keyfile"] = str(kwargs.get("keyfile"))

        class Stopped:
            server_address = ("127.0.0.1", 9)

            def serve_forever(self) -> None:
                raise KeyboardInterrupt

            def shutdown(self) -> None:
                return

        return Stopped()

    monkeypatch.setattr("a3p.dashboard.serve", fake_serve)
    assert main([
        "dashboard", "--history", str(history), "--allow-remote", "--token", "b" * 16,
        "--host", "127.0.0.1", "--tls", "--port", "0",
    ]) == 0
    assert seen["certfile"] and seen["certfile"].endswith("dashboard-cert.pem")
    assert main([
        "dashboard", "--history", str(history), "--allow-remote", "--token", "b" * 16,
        "--host", "127.0.0.1", "--tls-cert", str(cert), "--tls-key", str(key), "--port", "0",
    ]) == 0
    assert seen["certfile"] == str(cert)


def test_two_hundred_row_probe_slice(tmp_path: Path) -> None:
    report = run_live_scan(
        level="process",
        transport="stdio",
        output=tmp_path,
        probe_limit=200,
        allow_process=True,
    )
    assert len(report["probes"]) == 200
    assert report["elapsed_s"] < 120
    print(f"A3P_PROBE_200_ELAPSED_S={report['elapsed_s']}")
