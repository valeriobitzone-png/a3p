"""Named MCP servers, reply-aware script, bound Sigstore hash, dashboard token."""

from __future__ import annotations

import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from a3p.adaptive import AttackBudget, ScriptedAttacker
from a3p.adaptive_llm import AdaptiveAttacker, reply_aware_turn, reply_class
from a3p.cli import main
from a3p.corpus.probe_phrases import PHRASES
from a3p.dashboard import serve
from a3p.isolation import command_for
from a3p.mcp_bridge import _target
from a3p.mcp_bridge import main as bridge_main
from a3p.mcp_dynamic import McpScanError, parse_probe_limit, resolve_sandbox, run_live_scan
from a3p.ollama_proxy import serve as proxy_serve


def test_sandbox_argv_prefers_nsjail_and_runsc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    nsjail = command_for("nsjail", tmp_path / "escape", 9, program=["-m", "a3p.isolation_worker"])
    assert nsjail[0] == "nsjail"
    assert "--disable_clone_newnet" not in nsjail
    assert "--clone_newnet" not in nsjail
    assert nsjail[nsjail.index("--chroot") + 1] != "/"
    assert "--network" not in nsjail
    assert "--disable_no_new_privs" not in nsjail
    assert "--seccomp_policy" in nsjail
    policy = Path(nsjail[nsjail.index("--seccomp_policy") + 1])
    assert "ptrace" in policy.read_text(encoding="utf-8")
    runsc = command_for(
        "runsc",
        tmp_path / "escape",
        9,
        program=["-m", "a3p.isolation_worker"],
        extra_env={"A3P_MCP_UDS": "/opt/a3p-rw/mcp.sock"},
    )
    assert runsc[0] == "runsc"
    assert "--rootless" in runsc
    assert "--ignore-cgroups" in runsc
    assert "--network=none" in runsc
    assert "--platform=systrap" in runsc
    assert "run" in runsc
    bundle = Path(runsc[runsc.index("--bundle") + 1])
    spec = json.loads((bundle / "config.json").read_text(encoding="utf-8"))
    assert spec["process"]["noNewPrivileges"] is True
    assert any(item.startswith("A3P_MCP_UDS=") for item in spec["process"]["env"])
    assert "a3p.isolation_worker" in spec["process"]["args"]
    with pytest.raises(ValueError, match="absolute"):
        command_for("process", tmp_path, 9, program=["python3"], interpreter=False)
    monkeypatch.setattr("a3p.isolation.docker_prefix", lambda run=None: None)
    monkeypatch.setattr("a3p.isolation.shutil.which", lambda name: "/usr/bin/runsc" if name == "runsc" else None)
    from a3p.isolation import best_level

    assert best_level() == "runsc"
    monkeypatch.setattr(
        "a3p.isolation.shutil.which",
        lambda name: "/usr/bin/nsjail" if name == "nsjail" else ("/usr/bin/bwrap" if name == "bwrap" else None),
    )
    assert best_level() == "nsjail"
    with pytest.raises(McpScanError, match="unsafe"):
        resolve_sandbox("process", allow_process=False)
    assert resolve_sandbox("process", allow_process=True) == "process"


def test_probe_limit_and_named_stdio_server(tmp_path: Path) -> None:
    assert parse_probe_limit("4") == 4
    assert parse_probe_limit("all") is None
    with pytest.raises(McpScanError):
        parse_probe_limit("0")
    report = run_live_scan(
        level="process",
        transport="stdio",
        output=tmp_path,
        command=[sys.executable, "-m", "a3p.mcp_vulnerable"],
        probes=[{"id": "one", "language": "en", "text": "note"}],
        allow_process=True,
        invoke_destructive=True,
    )
    assert report["command"][0] == sys.executable
    assert any(item["kind"] == "destructive-invoked" and "not executed" in item["summary"] for item in report["findings"])
    assert main(
        ["mcp-scan", "--live", "--sandbox", "process", "--output", str(tmp_path / "refused")]
    ) == 1
    assert main(
        ["mcp-scan", "--live", "--transport", "sse", "--url", "http://127.0.0.1:9", "--output", str(tmp_path / "nourl")]
    ) == 2
    assert main(
        ["mcp-scan", "--live", "--transport", "sse", "--url", "http://example.com:9", "--command", sys.executable]
    ) == 1


def test_tcp_bridge_reaches_the_demo(tmp_path: Path) -> None:
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    port = int(holder.getsockname()[1])
    holder.close()
    report = run_live_scan(
        level="process",
        transport="sse",
        output=tmp_path,
        command=[sys.executable, "-m", "a3p.mcp_vulnerable"],
        tcp_port=port,
        server_env={"A3P_MCP_SSE_PORT": str(port)},
        probes=[{"id": "one", "language": "en", "text": "note"}],
        allow_process=True,
    )
    assert report["tcp_port"] == port
    assert report["network"] == "open"
    assert any(item["kind"] == "secret" for item in report["findings"])


@pytest.mark.integration
def test_container_tcp_bridge_keeps_network_none(tmp_path: Path) -> None:
    import os

    from a3p.isolation import _image_present, docker_prefix

    if not (docker_prefix() and _image_present(None)):
        if os.environ.get("A3P_REQUIRE_DOCKER") == "1":
            pytest.fail("Docker and the sandbox image were required and are not available")
        pytest.skip("Docker sandbox image is not available")
    report = run_live_scan(
        level="container",
        transport="sse",
        output=tmp_path,
        tcp_port=8765,
        probes=[{"id": "one", "language": "en", "text": "note"}],
    )
    assert report["network"] == "denied"
    assert report["sandbox"] == "container"
    assert any(item["kind"] == "secret" for item in report["findings"])


def test_bridge_copies_bytes_and_refuses_other_hosts(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        _target("10.0.0.1:80")
    echo = socket.socket()
    echo.bind(("127.0.0.1", 0))
    echo.listen(1)
    port = int(echo.getsockname()[1])

    def accept() -> None:
        conn, _addr = echo.accept()
        data = conn.recv(16)
        conn.sendall(b"pong:" + data)
        conn.close()

    threading.Thread(target=accept, daemon=True).start()
    sock = tmp_path / "bridge.sock"
    thread = threading.Thread(
        target=bridge_main,
        args=([
            "--listen",
            str(sock),
            "--target",
            f"127.0.0.1:{port}",
            "--",
            sys.executable,
            "-c",
            "import time; time.sleep(3)",
        ],),
        daemon=True,
    )
    thread.start()
    deadline = __import__("time").time() + 5
    while not sock.exists() and __import__("time").time() < deadline:
        __import__("time").sleep(0.02)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(sock))
    client.sendall(b"hi")
    assert client.recv(16) == b"pong:hi"
    client.close()
    echo.close()


def test_reply_branch_is_deterministic_and_marked() -> None:
    assert reply_class("") == "empty"
    assert reply_class("I cannot help") == "refusal"
    assert reply_class("x" * 200) == "long"
    empty, origin = reply_aware_turn("goal", "paraphrase", "en", 0, "")
    refused, _origin = reply_aware_turn("goal", "paraphrase", "en", 0, "I cannot help")
    again, _origin = reply_aware_turn("goal", "paraphrase", "en", 0, "I cannot help")
    assert empty != refused
    assert refused == again
    assert origin == ""
    translated, marked = reply_aware_turn("goal", "translation", "zh", 0, "")
    assert marked == "machine"
    assert "[machine]" in translated
    reviewed, reviewed_mark = reply_aware_turn("goal", "translation", "it", 0, "non posso")
    assert reviewed_mark == "reviewed"
    assert PHRASES["it"]["retry"] in reviewed
    assert set(PHRASES) == {"en", "it", "es", "fr", "de", "pt", "zh", "ja", "ru", "ar", "hi"}
    assert {row["origin"] for row in PHRASES.values()} == {"reviewed", "machine"}
    left = AdaptiveAttacker("office hours", seed=6, budget=AttackBudget(max_turns=1, max_calls=1))
    right = AdaptiveAttacker("office hours", seed=6, budget=AttackBudget(max_turns=1, max_calls=1))
    reply = [{"role": "assistant", "content": "I cannot help"}]
    assert left.next_message(reply) == right.next_message(list(reply))
    assert left.generated[0]["translation_origin"] == "machine"
    assert ScriptedAttacker(["fixed"]).next_message([{"role": "assistant", "content": "no"}]) == "fixed"


def test_ollama_proxy_requires_the_token(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            body = b"pong"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = int(upstream.server_address[1])
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    sock = tmp_path / "ollama.sock"
    proxy = proxy_serve(str(sock), f"http://127.0.0.1:{port}", "t" * 16)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    try:
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(sock)), timeout=5) as client:
            denied = client.get("http://localhost/api/tags")
            allowed = client.get("http://localhost/api/tags", headers={"Authorization": "Bearer " + ("t" * 16)})
        assert denied.status_code == 401
        assert allowed.status_code == 200
        assert allowed.content == b"pong"
    finally:
        proxy.shutdown()
        upstream.shutdown()
        proxy.server_close()
        upstream.server_close()


def test_dashboard_token_gates_the_page(tmp_path: Path) -> None:
    (tmp_path / "results.json").write_text(json.dumps({"overall": 1, "band": "fail", "results": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="token"):
        serve(tmp_path, host="0.0.0.0", port=0)
    server = serve(tmp_path, host="127.0.0.1", port=0, token="s" * 16)
    port = int(server.server_address[1])
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with httpx.Client(timeout=5) as client:
            denied = client.get(f"http://127.0.0.1:{port}/")
            allowed = client.get(f"http://127.0.0.1:{port}/", headers={"Authorization": "Bearer " + ("s" * 16)})
        assert denied.status_code == 401
        assert allowed.status_code == 200
        assert "A3P run history" in allowed.text
    finally:
        server.shutdown()
        server.server_close()
    assert main(["dashboard", "--history", str(tmp_path), "--host", "0.0.0.0", "--allow-remote", "--token", "short"]) == 2
