"""Method v1.0, badges, egress, and the Ollama plan."""

from __future__ import annotations

import json
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a3p.adapters.openai_chat import OpenAIChatAdapter
from a3p.config import ConfigError, load_config
from a3p.demo import demo_isolation_note
from a3p.egress import EgressProxy, _split_host
from a3p.handler_exec import HandlerSpec
from a3p.hosted import all_scenarios
from a3p.leaderboard import collect, load_badge, render_site
from a3p.method import (
    components_for,
    coverage_markdown,
    criteria_from_report,
    level_for,
    model_component,
    render_badge_svg,
    repro_bundle,
    sign_badge,
    statement,
    verify_badge,
)
from a3p.ollama_isolation import attested, commands, limits
from a3p.runner import _seed_count
from a3p.sandbox import invoke_tool


def _criteria(**overrides: object) -> dict:
    base: dict = {
        "batteries_complete": True,
        "seeds": 1,
        "ledger_head": "abc",
        "handlers": "in-process",
        "tool_level": "inprocess",
        "network_denied": False,
        "host_marker_intact": False,
        "model_level": "scripted",
        "handlers_inprocess": 1,
    }
    base.update(overrides)
    return base


def test_levels_match_the_method():
    assert level_for({"seeds": 0}) == "A3P-L0"
    assert level_for(_criteria()) == "A3P-L1"
    assert statement("A3P-L1") == "assessed under A3P Method v1.0, level A3P-L1"
    assert "guaranteed" not in statement("A3P-L3").lower()
    with pytest.raises(ValueError):
        statement("A3P-L9")
    repeated = _criteria(seeds=2, handlers="sandboxed", tool_level="process", handlers_inprocess=0)
    assert level_for(repeated) == "A3P-L2"
    isolated = _criteria(
        seeds=2,
        handlers="sandboxed",
        tool_level="container",
        network_denied=True,
        host_marker_intact=True,
        model_level="egress-proxy",
        handlers_inprocess=0,
    )
    assert level_for(isolated) == "A3P-L2"
    isolated["tls_intercept"] = True
    assert level_for(isolated) == "A3P-L3"
    nsjail = dict(isolated)
    nsjail["tool_level"] = "nsjail"
    assert level_for(nsjail) == "A3P-L3"
    runsc = dict(isolated)
    runsc["tool_level"] = "runsc"
    assert level_for(runsc) == "A3P-L3"
    scripted = dict(isolated)
    scripted["model_level"] = "scripted"
    assert level_for(scripted) == "A3P-L2"
    assert model_component("mock://careful", proxy=None, ollama_isolated=False)["level"] == "scripted"
    assert model_component("https://api.x.ai/v1", proxy="http://127.0.0.1:9", ollama_isolated=False)["level"] == "egress-proxy"
    assert model_component("http://127.0.0.1:11434", proxy=None, ollama_isolated=True)["level"] == "ollama-container"
    direct = model_component("https://api.x.ai/v1", proxy=None, ollama_isolated=False)
    assert direct["level"] == "direct"
    assert "subprocess" in components_for("process", {"network": "open"}, None)["tools"]["note"]
    assert "JSON channel" in components_for("bwrap", {"network": "denied"}, None)["tools"]["note"]
    assert "inprocess" in components_for("inprocess", {}, None)["tools"]["note"].lower()
    assert criteria_from_report({"batteries": [], "meta": {}})["tool_level"] == "inprocess"


def test_unattested_ollama_env_is_not_a_container(monkeypatch):
    monkeypatch.setenv("A3P_OLLAMA_ISOLATION", "container")
    seen = model_component("http://127.0.0.1:11434", proxy=None, ollama_isolated=False)
    assert seen["level"] == "direct"
    assert "does not claim ollama-container" in seen["detail"]


def test_badge_signature_and_wording():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    body = {
        "method_version": "1.0",
        "level": "A3P-L1",
        "statement": statement("A3P-L1"),
        "public_key_hex": public,
        "agent_name": "A & B",
        "overall": 80,
        "band": "pass",
        "criteria": _criteria(),
        "phantom_failed": 0,
        "phantom_total": 4,
        "phantom_score": 100,
    }
    signed = sign_badge(body, key)
    ok, reason = verify_badge(signed)
    assert ok, reason
    svg = render_badge_svg(signed)
    assert "assessed under A3P Method v1.0, level A3P-L1" in svg
    assert "A &amp; B" in svg
    flipped = dict(signed)
    flipped["level"] = "A3P-L3"
    assert verify_badge(flipped)[0] is False
    mismatched = dict(body)
    mismatched["level"] = "A3P-L3"
    mismatched["statement"] = statement("A3P-L3")
    assert "criteria" in verify_badge(sign_badge(mismatched, key))[1]
    claimed = dict(body)
    claimed["statement"] = "guaranteed safe"
    assert "guarantee" in verify_badge(sign_badge(claimed, key))[1]
    assert verify_badge({"statement": "x"})[0] is False
    unknown = dict(body)
    unknown["level"] = "nope"
    assert "unknown level" in verify_badge(sign_badge(unknown, key))[1]
    drifted = dict(body)
    drifted["statement"] = "assessed under a different sentence"
    assert "does not match" in verify_badge(sign_badge(drifted, key))[1]
    shapeless = dict(body)
    shapeless["criteria"] = []
    assert "criteria" in verify_badge(sign_badge(shapeless, key))[1]
    missing_key = dict(signed)
    missing_key["public_key_hex"] = ""
    assert "public key" in verify_badge(missing_key)[1]
    bundle = repro_bundle({"meta": {"seeds": 2, "assessment": statement("A3P-L1"), "assurance_level": "A3P-L1"}})
    assert bundle["method_version"] == "1.0"
    assert bundle["corpus_sha256"]
    assert "not make the agent safe" in bundle["limits"]


def test_every_battery_handler_has_a_spec_and_closures_are_refused(monkeypatch):
    for scenario in all_scenarios():
        world, tools = scenario.build_tools()
        for bound in tools:
            assert isinstance(getattr(bound.handler, "_spec", None), HandlerSpec)
            assert getattr(bound.handler, "_world", None) is world
    called: list[dict] = []

    def bare(arguments: dict) -> dict:
        called.append(arguments)
        return {"ok": True}

    monkeypatch.setenv("A3P_ISOLATION", "process")
    refused = invoke_tool(bare, {"x": 1})
    assert refused["error"] == "refused to run a handler in-process"
    assert called == []
    bare._spec = HandlerSpec(kind="echo", echo="ok")  # type: ignore[attr-defined]
    monkeypatch.setenv("A3P_ISOLATION", "bwrap")
    refused_again = invoke_tool(bare, {})
    assert refused_again["isolation"] == "bwrap"
    assert called == []


def test_egress_allow_list_redacts_and_tunnels(tmp_path: Path):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            body = json.dumps(
                {"choices": [{"message": {"role": "assistant", "content": "done"}}]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    proxy = EgressProxy({"127.0.0.1"}, tmp_path / "egress.log")
    proxy_url = proxy.start()
    try:
        adapter = OpenAIChatAdapter(
            base_url=f"http://127.0.0.1:{port}/v1",
            model="m",
            api_key="super-secret-token",
            proxy=proxy_url,
            retries=0,
        )
        result = adapter.run(task="hi", system="sys", tools=[])
        assert result.final_text == "done"
        log = (tmp_path / "egress.log").read_text(encoding="utf-8")
        assert "super-secret-token" not in log
        assert "[redacted]" in log
        denied = httpx.get("http://192.0.2.1/", proxy=proxy_url, timeout=5)
        assert denied.status_code == 403
        proxy_port = int(urlsplit(proxy_url).port or 0)
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
            sock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            sock.settimeout(2)
            data = _read_headers(sock)
        assert b"403" in data
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
            sock.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
            sock.settimeout(2)
            data = _read_headers(sock)
        assert b"502" in data
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
            sock.sendall(
                f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()
            )
            sock.settimeout(2)
            opened = _read_headers(sock)
            assert b"200" in opened
            payload = b"{}"
            sock.sendall(
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\n" + payload
            )
            body = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body += chunk
        assert b"200" in body
        proxy.record("GET", "127.0.0.1", None)
        proxy.record("GET", "127.0.0.1", "GET")
        assert "absent" in (tmp_path / "egress.log").read_text(encoding="utf-8")
    finally:
        proxy.stop()
        proxy.stop()
        server.shutdown()
        server.server_close()
    assert _split_host("example.com", 443) == ("example.com", 443)
    assert _split_host("example.com:80", 443) == ("example.com", 80)
    assert _split_host("example.com:nope", 443) == ("example.com", 443)


def _read_headers(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data


def test_ollama_plan_and_attest(monkeypatch, tmp_path):
    planned = commands(tmp_path, "a" * 16)
    assert planned[0][:4] == ["docker", "network", "create", "--internal"]
    assert "-p" not in planned[1]
    assert "--cap-drop" in planned[1] and "ALL" in planned[1]
    joined = " ".join(planned[2])
    assert "A3P_OLLAMA_TOKEN=" not in joined
    assert "A3P_OLLAMA_TOKEN_FILE=/opt/a3p-socks/token" in planned[2]
    assert (tmp_path / "token").read_text(encoding="utf-8").strip() == "a" * 16
    assert "a" * 16 not in joined
    assert "a3p.ollama_proxy" in planned[2]
    with pytest.raises(ValueError):
        commands(tmp_path, "short")
    with pytest.raises(ValueError):
        commands(Path("relative"), "a" * 16)
    payload = {
        "NetworkSettings": {"Networks": {"a3p-ollama": {}}},
        "HostConfig": {"PortBindings": {}},
    }

    def fake(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([payload]), stderr="")

    monkeypatch.setattr("a3p.ollama_isolation.docker_prefix", lambda run=None: ["docker"])
    assert attested(run=fake) is True

    def published(cmd, **kwargs):
        shifted = json.loads(json.dumps(payload))
        shifted["HostConfig"]["PortBindings"] = {"11434/tcp": [{"HostIp": "127.0.0.1", "HostPort": "11434"}]}
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([shifted]), stderr="")

    assert attested(run=published) is False
    monkeypatch.setattr("a3p.ollama_isolation.docker_prefix", lambda run=None: None)
    assert attested(run=fake) is False
    monkeypatch.setattr("a3p.ollama_isolation.docker_prefix", lambda run=None: ["docker"])

    def broken(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="missing")

    assert attested(run=broken) is False

    def garbage(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="nope", stderr="")

    assert attested(run=garbage) is False

    def explode(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 8)

    assert attested(run=explode) is False
    proc = subprocess.run(
        ["python3", "scripts/run_ollama_isolated.py", "--sock-dir", str(tmp_path / "socks")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "--internal" in proc.stdout
    assert "unix socket" in limits()
    assert "--run" not in proc.stdout

    def inspect_with(stdout: str):
        def run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

        return run

    monkeypatch.setattr("a3p.ollama_isolation.docker_prefix", lambda run=None: ["docker"])
    assert attested(run=inspect_with("[]")) is False
    assert attested(run=inspect_with("[null]")) is False
    assert attested(run=inspect_with(json.dumps([{"NetworkSettings": {"Networks": []}}]))) is False
    assert attested(run=inspect_with(json.dumps([{"NetworkSettings": {"Networks": {}}, "HostConfig": {"PortBindings": []}}]))) is False
    assert attested(
        run=inspect_with(
            json.dumps([{"NetworkSettings": {"Networks": {"a3p-ollama": {}}}, "HostConfig": {"PortBindings": {"11434/tcp": "no"}}}])
        )
    ) is False
    assert attested(
        run=inspect_with(
            json.dumps(
                [
                    {
                        "NetworkSettings": {"Networks": {"a3p-ollama": {}}},
                        "HostConfig": {"PortBindings": {"11434/tcp": ["nope", {"HostIp": "0.0.0.0", "HostPort": "11434"}]}},
                    }
                ]
            )
        )
    ) is False


def test_leaderboard_rejects_a_bad_badge(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    signed = sign_badge(
        {
            "level": "A3P-L1",
            "statement": statement("A3P-L1"),
            "public_key_hex": public,
            "criteria": _criteria(),
            "agent_name": "kept",
            "phantom_failed": 1,
            "phantom_total": 4,
            "phantom_score": 75,
            "overall": 70,
            "band": "review",
        },
        key,
    )
    good = tmp_path / "good"
    good.mkdir()
    (good / "badge.json").write_text(json.dumps(signed), encoding="utf-8")
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "badge.json").write_text(json.dumps({"signature": "00", "level": "A3P-L1"}), encoding="utf-8")
    board = collect([good, bad, tmp_path / "missing"])
    assert board["rows"][0]["phantom_success_rate"] == 0.25
    assert board["rows"][0]["statement"].startswith("assessed under A3P Method v1.0")
    assert len(board["rejected"]) == 2
    page = render_site(board)
    assert "0.2500" in page
    assert "guaranteed safe" not in page.lower()
    assert "Rejected" in page
    (tmp_path / "list.json").write_text("[]", encoding="utf-8")
    assert load_badge(tmp_path / "list.json") is None
    empty = render_site({"method_version": "1.0", "rows": [], "rejected": []})
    assert "No verified badge" in empty
    assert "None." in empty


def test_coverage_names_the_frameworks_and_the_gaps():
    text = coverage_markdown()
    for token in (
        "LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
        "ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10",
        "AML.T0051", "AML.T0053", "AML.T0054", "AML.T0024", "AML.T0040", "AML.T0043",
        "art. 50", "leak-art50",
    ):
        assert token in text
    assert "100%" in text
    assert "Not labeled" not in text


def test_seeds_config_and_demo_note(tmp_path: Path, monkeypatch):
    assert _seed_count(None) == 1
    assert _seed_count("2") == 2
    assert _seed_count("nope") == 1
    assert _seed_count(99) == 8
    path = tmp_path / "probe.yaml"
    path.write_text("seeds: 2\n", encoding="utf-8")
    assert load_config(path).seeds == 2
    path.write_text("seeds: 9\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)
    monkeypatch.delenv("A3P_ISOLATION", raising=False)
    note = demo_isolation_note()
    assert note is not None and "in-process" in note
    assert demo_isolation_note() is None
