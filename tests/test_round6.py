"""TLS intercept, catalog oracles, scan, and the runtime guard."""

from __future__ import annotations

import io
import json
import os
import socket
import ssl
import threading
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization

from a3p.adapters.callable_agent import CallableAdapter
from a3p.batteries.common import run_scenario
from a3p.batteries.framework import framework_scenarios
from a3p.canaries import JAILBREAK_MARKER
from a3p.cli import main
from a3p.egress import EgressProxy, issue_ca, issue_leaf
from a3p.env import setting
from a3p.guard import REFUSAL, GuardServer, guard_text
from a3p.isolation import command_for
from a3p.mappings import ASI, ATLAS, LLM
from a3p.method import coverage_rows
from a3p.sarif_out import render_sarif
from a3p.tui import LiveProgress


def test_framework_oracles_split_the_two_policies():
    careful = CallableAdapter("careful")
    vulnerable = CallableAdapter("vulnerable")
    ids = [scenario.id for scenario in framework_scenarios()]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 14
    for scenario in framework_scenarios():
        ok = run_scenario(careful, scenario)
        bad = run_scenario(vulnerable, scenario)
        assert ok.passed, scenario.id
        assert not bad.passed, scenario.id


def test_named_catalogs_are_on_scored_rows():
    refs = {row["ref"] for row in coverage_rows()}
    assert set(LLM) <= refs
    assert set(ASI) <= refs
    assert set(ATLAS) <= refs


def test_tls_intercept_redacts_canaries_and_pins_the_provider(tmp_path: Path):
    upstream_ca, upstream_key = issue_ca()
    leaf_pem, leaf_key = issue_leaf(upstream_ca, upstream_key, "127.0.0.1")
    ca_path = tmp_path / "upstream-ca.pem"
    cert_path = tmp_path / "upstream.crt"
    key_path = tmp_path / "upstream.key"
    ca_path.write_bytes(upstream_ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_pem)
    key_path.write_bytes(leaf_key)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            body = b'{"ok":true,"echo":"PWNED-A3PROBE"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = int(httpd.server_address[1])
    before = os.environ.get("SSL_CERT_FILE")
    proxy = EgressProxy(
        {"127.0.0.1"},
        tmp_path / "egress.log",
        intercept=True,
        path_allow={"127.0.0.1": ("/ok",)},
        canaries=(JAILBREAK_MARKER,),
        upstream_ca=str(ca_path),
    )
    proxy_url = proxy.start()
    try:
        assert os.environ.get("SSL_CERT_FILE") == before
        assert proxy.ca_path is not None
        with httpx.Client(
            proxy=proxy_url,
            verify=ssl.create_default_context(cafile=str(proxy.ca_path)),
            timeout=5,
            trust_env=False,
        ) as client:
            accepted = client.post(f"https://127.0.0.1:{port}/ok", content=b"token PWNED-A3PROBE sk-supersecretkey")
            denied = client.get(f"https://127.0.0.1:{port}/secret")
        assert accepted.status_code == 200
        assert denied.status_code == 403
        log = (tmp_path / "egress.log").read_text(encoding="utf-8")
        assert JAILBREAK_MARKER not in log
        assert "sk-supersecretkey" not in log
        assert "[redacted-canary]" in log or "[redacted" in log
        assert any(hit["needle"] == JAILBREAK_MARKER for hit in proxy.exfil_hits)
        assert "PRIVATE KEY" not in log
        _reject_wrong_host(proxy_url, str(proxy.ca_path), port)
    finally:
        proxy.stop()

    pinned = EgressProxy(
        {"127.0.0.1"},
        tmp_path / "pinned.log",
        intercept=True,
        pin_hosts={"127.0.0.1"},
        upstream_ca=str(ca_path),
    )
    pinned_url = pinned.start()
    try:
        with httpx.Client(
            proxy=pinned_url,
            verify=ssl.create_default_context(cafile=str(ca_path)),
            timeout=5,
            trust_env=False,
        ) as client:
            direct = client.get(f"https://127.0.0.1:{port}/ok")
        assert direct.status_code == 200
        pinned_log = (tmp_path / "pinned.log").read_text(encoding="utf-8")
        assert '"intercept": false' in pinned_log or '"pinned": true' in pinned_log
        assert pinned.exfil_hits == []
    finally:
        pinned.stop()
        httpd.shutdown()
        httpd.server_close()


def _reject_wrong_host(proxy_url: str, ca_file: str, port: int) -> None:
    proxy_port = int(httpx.URL(proxy_url).port or 0)
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    sock.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
    data = b""
    sock.settimeout(5)
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    assert b"200" in data
    context = ssl.create_default_context(cafile=ca_file)
    tls = context.wrap_socket(sock, server_hostname="127.0.0.1")
    tls.sendall(b"GET /ok HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
    body = b""
    while True:
        try:
            chunk = tls.recv(1024)
        except OSError:
            break
        if not chunk:
            break
        body += chunk
    tls.close()
    assert b"403" in body


def test_sandbox_command_mounts_the_ca_without_touching_the_host(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    ca = tmp_path / "ca.pem"
    ca.write_text("ca", encoding="utf-8")
    command = command_for("container", tmp_path / "escape", 9, ["docker"], ca_cert=str(ca))
    joined = " ".join(command)
    assert "/opt/a3p-ca.pem" in joined
    assert "SSL_CERT_FILE=/opt/a3p-ca.pem" in joined
    assert os.environ.get("SSL_CERT_FILE") is None
    wrapped = " ".join(command_for("bwrap", tmp_path / "escape", 9, ca_cert=str(ca)))
    assert "/opt/a3p-ca.pem" in wrapped


def test_legacy_env_and_cli_alias(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("A3P_ISOLATION", raising=False)
    monkeypatch.setenv("A3PROBE_ISOLATION", "process")
    assert setting("ISOLATION") == "process"
    monkeypatch.setenv("A3P_ISOLATION", "")
    assert setting("ISOLATION") == ""
    monkeypatch.setenv("A3P_KEY_DIR", str(tmp_path / "keys"))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        import a3probe

        assert a3probe.__version__
        assert any(issubclass(item.category, DeprecationWarning) for item in caught)


def test_scan_writes_sarif_and_guard_blocks_unverified_claims(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("A3P_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("A3P_ISOLATION", "inprocess")
    config = tmp_path / "probe.yaml"
    config.write_text(
        "meta:\n  client: Northwind\n  agent_name: scan-demo\n  agent_version: '0'\n"
        "  scope: unit\n  auditor: test\n"
        "target:\n  adapter: callable\n  policy: vulnerable\n"
        "batteries:\n  - phantom\n"
        "output:\n  directory: out/ignored\n",
        encoding="utf-8",
    )
    sarif_path = tmp_path / "a3p.sarif"
    assert main(["scan", str(config), "-o", str(tmp_path / "scan"), "--sarif", str(sarif_path)]) == 0
    captured = capsys.readouterr()
    assert "assessed under A3P Method v1.0" in captured.out
    assert "phantom-" in captured.err
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    html = (tmp_path / "scan" / "report.html").read_text(encoding="utf-8")
    assert "Executive summary" in html
    assert "agent claim" in html
    assert "A3P-L" in html
    allow, shown = guard_text("No action was taken.", [])
    assert allow and shown.startswith("No action")
    blocked, refusal = guard_text("Done: the email was sent.", [{"ok": True}])
    assert blocked is False and refusal == REFUSAL
    allowed, kept = guard_text("Done: the email was sent.", [{"world_verified": True}])
    assert allowed and "sent" in kept
    empty = render_sarif({"results": [], "meta": {}})
    assert empty["runs"][0]["results"] == []
    server = GuardServer("127.0.0.1", 0)
    url = server.start()
    try:
        response = httpx.post(url + "/v1/screen", json={"text": "Done: the email was sent.", "tool_results": []}, timeout=5)
        assert response.json()["allow"] is False
        mcp = httpx.post(
            url + "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "screen", "arguments": {"text": "I will send it tomorrow.", "tool_results": []}},
            },
            timeout=5,
        )
        assert mcp.json()["result"]["isError"] is False
        listed = httpx.post(url + "/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, timeout=5)
        assert listed.json()["result"]["tools"][0]["name"] == "screen"
        bad = httpx.post(url + "/v1/screen", content=b"not-json", timeout=5)
        assert bad.status_code == 400
        missing = httpx.post(url + "/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "nope"}, timeout=5)
        assert missing.json()["error"]["code"] == -32601
    finally:
        server.stop()
    with pytest.raises(ValueError):
        GuardServer("0.0.0.0", 9)
    medium = render_sarif(
        {"results": [{"passed": False, "scenario_id": "m", "title": "m", "summary": "s", "fail_severity": "medium", "remediation": "r"}], "meta": {}}
    )
    assert medium["runs"][0]["results"][0]["level"] == "warning"
    low = render_sarif(
        {"results": [{"passed": False, "scenario_id": "l", "title": "l", "summary": "s", "fail_severity": "low"}], "meta": {}}
    )
    assert low["runs"][0]["results"][0]["level"] == "note"

    class _Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    stream = _Tty()
    progress = LiveProgress(1, stream)
    progress(type("R", (), {"passed": False, "battery": "phantom", "scenario_id": "x"})())
    progress.close()
    assert "FAIL" in stream.getvalue()
    assert main(["guard", "--host", "0.0.0.0"]) == 2
