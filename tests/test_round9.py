"""Round 9: Sigstore when OIDC exists, live MCP proxy, attacker strategies, services."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a3p.adaptive import STRATEGIES, AttackBudget, StrategyAttacker, run_adaptive_chat
from a3p.attest import (
    KeylessUnavailable,
    ambient_identity,
    sign_keyless,
    sign_result,
    sigstore_verify_command,
    statement_for,
    verify_envelope,
)
from a3p.cli import main
from a3p.mcp_proxy import ToolGate
from a3p.world.sql import connect_postgres

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "mcp_example_server.py"
SRC = str(ROOT / "src")


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _wait_port(port: int, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} did not open")


def docker_endpoint() -> str | None:
    """Return a Docker API that answers ping. Does not change the process environment."""
    try:
        import docker
    except ImportError:
        return None
    candidates: list[str] = []
    configured = os.environ.get("DOCKER_HOST")
    if configured:
        candidates.append(configured)
    if Path("/var/run/docker.sock").exists():
        candidates.append("unix:///var/run/docker.sock")
    if "tcp://127.0.0.1:2375" not in candidates:
        candidates.append("tcp://127.0.0.1:2375")
    for base in candidates:
        client = None
        try:
            client = docker.DockerClient(base_url=base, timeout=3)
            client.ping()
            return base
        except Exception:
            continue
        finally:
            if client is not None:
                client.close()
    return None


def docker_ready() -> bool:
    return docker_endpoint() is not None


def minio_binary() -> str | None:
    for candidate in (os.environ.get("MINIO_BIN"), "/usr/local/bin/minio", "/tmp/minio"):
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def test_tool_gate_pins_allow_list_and_rug_pull() -> None:
    gate = ToolGate(allow={"add"})
    first = gate.observe(
        [{"name": "add", "description": "Add two integers.", "inputSchema": {"type": "object"}}, {"name": "secret", "description": "no", "inputSchema": {}}]
    )
    assert [item["name"] for item in first] == ["add"]
    assert any(item["kind"] == "denied" for item in gate.findings)
    assert gate.allow_call("add") is None
    assert gate.allow_call("secret")
    changed = gate.observe([{"name": "add", "description": "Add two integers. now different.", "inputSchema": {"type": "object"}}])
    assert changed == []
    assert any(item["kind"] == "rug-pull" for item in gate.findings)
    assert "blocked" in (gate.allow_call("add") or "")
    pinned = ToolGate(pins={"add": "0" * 64})
    pinned.observe([{"name": "add", "description": "x", "inputSchema": {}}])
    assert any(item["kind"] == "rug-pull" for item in pinned.findings)
    assert ToolGate().allow_call("missing")


def test_keyless_without_oidc_falls_back_to_ed25519(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    document = statement_for("results.json", b"{}", {"statement": "assessed under A3P Method v1.0, level A3P-L0"})
    key = Ed25519PrivateKey.generate()
    try:
        sign_keyless(document)
    except KeylessUnavailable as exc:
        assert "OIDC" in str(exc) or "sigstore" in str(exc).lower()
    else:
        raise AssertionError("keyless signing ran without an operator token")
    sealed = sign_result(document, key)
    assert sealed["kind"] == "ed25519-dsse"
    assert verify_envelope(sealed["envelope"])["predicateType"]
    monkeypatch.setattr(
        "a3p.attest.ambient_identity",
        lambda: SimpleNamespace(identity="user@example.com", issuer="https://issuer.example"),
    )

    class _Bundle:
        def to_json(self) -> str:
            return json.dumps({"mediaType": "application/vnd.dev.sigstore.bundle+json", "tlogEntries": []})

    monkeypatch.setattr("a3p.attest._production_sign", lambda payload, identity: _Bundle())
    bundle = sign_keyless(document)
    assert bundle["identity"] == "user@example.com"
    assert bundle["artifactSha256"] == hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    both = sign_result(document, key)
    assert both["kind"] == "sigstore-bundle" and "envelope" in both
    statement = tmp_path / "statement.json"
    statement.write_text("{", encoding="utf-8")
    assert main(["sign-keyless", str(statement), "-o", str(tmp_path / "out.json")]) == 1
    statement.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr("a3p.attest.sign_keyless", lambda doc: (_ for _ in ()).throw(KeylessUnavailable("No ambient OIDC token")))
    assert main(["sign-keyless", str(statement), "-o", str(tmp_path / "out.json")]) == 2
    command = sigstore_verify_command("a.json", "b.json", "user@example.com", "https://issuer.example")
    assert command[1:6] == ["-m", "sigstore", "verify", "identity", "--bundle"]
    assert main(["verify-sigstore", str(statement), str(statement), "--identity", "x", "--issuer", "https://example.invalid"]) == 1
    assert main(["mcp-proxy", "--host", "0.0.0.0"]) == 2
    assert main(["mcp-proxy"]) == 2


def test_ambient_identity_rejects_a_bad_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sigstore.oidc.detect_credential", lambda: "not-a-jwt")
    with pytest.raises(KeylessUnavailable, match="OIDC"):
        ambient_identity()


def test_production_sign_uses_the_sigstore_context(monkeypatch: pytest.MonkeyPatch) -> None:
    from a3p.attest import _production_sign

    seen: dict[str, bytes] = {}

    class _Signer:
        def sign_artifact(self, payload: bytes) -> str:
            seen["payload"] = payload
            return "bundle"

    class _Context:
        def signer(self, identity: object) -> Any:
            from contextlib import contextmanager

            @contextmanager
            def opened() -> Iterator[_Signer]:
                yield _Signer()

            return opened()

    monkeypatch.setattr("sigstore.models.ClientTrustConfig.production", staticmethod(lambda: object()))
    monkeypatch.setattr("sigstore.sign.SigningContext.from_trust_config", staticmethod(lambda config: _Context()))
    assert _production_sign(b"abc", object()) == "bundle"
    assert seen["payload"] == b"abc"


def test_strategy_budget_and_cassette(tmp_path: Path) -> None:
    cassette = json.loads((ROOT / "tests" / "fixtures" / "attacker_cassette.json").read_text(encoding="utf-8"))
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            seen.append(str(body["messages"][0]["content"]))
            turn = len([item for item in body["messages"] if item.get("role") == "user"])
            text = cassette["turns"][min(turn, len(cassette["turns"])) - 1]
            payload = {"choices": [{"message": {"role": "assistant", "content": text}}]}
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        attacker = StrategyAttacker(
            f"http://127.0.0.1:{port}/v1",
            "cassette",
            "Ask about a public status page.",
            "crescendo",
            budget=AttackBudget(max_turns=2, max_calls=2, max_chars=80),
            timeout=5,
        )
        messages = run_adaptive_chat(lambda _messages: "It is a status page.", attacker, task="Begin.", max_turns=2)
    finally:
        server.shutdown()
    assert attacker.calls == 2
    user_turns = [item["content"] for item in messages if item["role"] == "user"]
    assert user_turns[1:] == cassette["turns"]
    assert "crescendo" in seen[0]
    with pytest.raises(ValueError, match="unknown strategy"):
        StrategyAttacker("http://127.0.0.1", "m", "goal", "not-a-strategy")
    assert set(STRATEGIES) == {"crescendo", "role-play", "encoding", "tool-output"}
    short = StrategyAttacker(
        "http://127.0.0.1",
        "m",
        "goal",
        "encoding",
        budget=AttackBudget(max_turns=1, max_calls=1, max_chars=4),
        client=httpx.Client(base_url="http://mock.test/v1", transport=httpx.MockTransport(_one_shot)),
    )
    assert short.next_message([{"role": "user", "content": "go"}]) == "abcd"
    assert short.next_message([{"role": "user", "content": "go"}]) is None


def _one_shot(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": "abcdef"}}]})


def test_ollama_strategy_if_running() -> None:
    try:
        httpx.get("http://127.0.0.1:11434/api/tags", timeout=2).raise_for_status()
    except httpx.HTTPError:
        pytest.skip("ollama is not running")
    attacker = StrategyAttacker(
        "http://127.0.0.1:11434/v1",
        os.environ.get("A3P_OLLAMA_MODEL", "gemma2:2b"),
        "Ask for the office opening time in one short question.",
        "role-play",
        budget=AttackBudget(max_turns=1, max_calls=1, max_chars=240),
        timeout=90,
        max_tokens=80,
    )
    messages = run_adaptive_chat(lambda _messages: "The office opens at nine.", attacker, task="Start.", max_turns=1)
    assert attacker.calls == 1
    assert messages[-1]["role"] == "user"
    assert messages[-1]["content"]


def test_dashboard_in_a_browser(tmp_path: Path) -> None:
    playwright_sync = pytest.importorskip("playwright.sync_api")
    from a3p.dashboard import serve

    runs = tmp_path / "runs"
    older = runs / "monday"
    newer = runs / "tuesday"
    older.mkdir(parents=True)
    newer.mkdir()
    (older / "results.json").write_text(
        json.dumps({"overall": 80, "band": "review", "results": [{"scenario_id": "leak-art50", "passed": False}], "meta": {}}),
        encoding="utf-8",
    )
    (newer / "results.json").write_text(
        json.dumps(
            {
                "overall": 50,
                "band": "fail",
                "results": [{"scenario_id": "inj-direct-system", "passed": False}],
                "meta": {"assessment": "assessed under A3P Method v1.0, level A3P-L0"},
            }
        ),
        encoding="utf-8",
    )
    server = serve(runs, port=0)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    shot = tmp_path / "dashboard.png"
    try:
        with playwright_sync.sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1100, "height": 800})
            page.goto(f"http://127.0.0.1:{port}/", wait_until="domcontentloaded")
            page.get_by_role("heading", name="A3P run history").wait_for()
            assert "inj-direct-system" in page.locator("article").nth(1).inner_text()
            assert "not a certification" in page.inner_text("body").lower()
            page.screenshot(path=str(shot), full_page=True)
            mobile = browser.new_page(viewport={"width": 390, "height": 780})
            mobile.goto(f"http://127.0.0.1:{port}/", wait_until="domcontentloaded")
            overflow = mobile.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
            browser.close()
    finally:
        server.shutdown()
    assert shot.stat().st_size > 5000
    assert overflow < 8
    artifacts = Path(os.environ.get("A3P_ARTIFACTS_DIR", "artifacts"))
    try:
        if artifacts.is_dir():
            (artifacts / "dashboard.png").write_bytes(shot.read_bytes())
    except OSError:
        pass


def test_mcp_proxy_stdio_and_streamable_http(tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    desc = tmp_path / "desc.txt"
    desc.write_text("Add two integers.\n", encoding="utf-8")
    env = _env()
    env["A3P_MCP_DESC_FILE"] = str(desc)
    asyncio.run(_proxy_stdio(env, desc))
    asyncio.run(_proxy_http(env, desc))


async def _proxy_stdio(env: dict[str, str], desc: Path) -> None:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "a3p",
            "mcp-proxy",
            "--upstream-command",
            sys.executable,
            "--upstream-command",
            str(FIXTURE),
            "--allow",
            "add",
            "--upstream-env",
            f"A3P_MCP_DESC_FILE={desc}",
        ],
        env=env,
    )
    async with stdio_client(params) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = [tool.name for tool in listed.tools]
            assert names == ["add"]
            result = await session.call_tool("add", {"a": 2, "b": 3})
            assert "5" in result.content[0].text
            hidden = await session.call_tool("secret", {"token": "nope"})
            assert hidden.is_error
            desc.write_text("Add two integers. changed live.\n", encoding="utf-8")
            again = await session.list_tools()
            assert [tool.name for tool in again.tools] == []
            blocked = await session.call_tool("add", {"a": 1, "b": 1})
            assert blocked.is_error


async def _proxy_http(env: dict[str, str], desc: Path) -> None:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    desc.write_text("Add two integers.\n", encoding="utf-8")
    upstream_port = _free_port()
    proxy_port = _free_port()
    upstream_env = dict(env)
    upstream_env["A3P_MCP_TRANSPORT"] = "streamable-http"
    upstream_env["A3P_MCP_PORT"] = str(upstream_port)
    upstream = subprocess.Popen(
        [sys.executable, str(FIXTURE)],
        env=upstream_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    proxy = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "a3p",
            "mcp-proxy",
            "--upstream-url",
            f"http://127.0.0.1:{upstream_port}/mcp",
            "--downstream",
            "streamable-http",
            "--allow",
            "add",
            "--port",
            str(proxy_port),
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_port(upstream_port)
        _wait_port(proxy_port)
        async with streamable_http_client(f"http://127.0.0.1:{proxy_port}/mcp") as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                listed = await session.list_tools()
                assert [tool.name for tool in listed.tools] == ["add"]
                result = await session.call_tool("add", {"a": 4, "b": 1})
                assert "5" in result.content[0].text
    finally:
        proxy.terminate()
        upstream.terminate()
        proxy.wait(timeout=5)
        upstream.wait(timeout=5)


@pytest.mark.integration
def test_postgres_and_mailpit() -> None:
    if not docker_ready():
        if os.environ.get("A3P_REQUIRE_DOCKER") == "1":
            pytest.fail("Docker was required and is not available")
        pytest.skip("Docker is not available")
    endpoint = docker_endpoint()
    previous = os.environ.get("DOCKER_HOST")
    if endpoint:
        os.environ["DOCKER_HOST"] = endpoint
    try:
        _postgres_and_mailpit()
    finally:
        if previous is None:
            os.environ.pop("DOCKER_HOST", None)
        else:
            os.environ["DOCKER_HOST"] = previous


def _postgres_and_mailpit() -> None:
    from testcontainers.community.postgres import PostgresContainer
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.wait_strategies import HttpWaitStrategy

    from a3p.world.mail import MailpitVerifier
    from a3p.world.sql import PostgresVerifier

    with PostgresContainer("postgres:16-alpine") as postgres:
        connection = connect_postgres(postgres.get_connection_url(driver=None))
        try:
            connection.execute("CREATE TABLE notes (body text)")
            connection.execute("INSERT INTO notes (body) VALUES ('sealed')")
            connection.commit()
            seen = PostgresVerifier(connection).read({"sql": "SELECT body FROM notes WHERE body = %s", "params": ["sealed"], "expect_rows": 1})
            refused = PostgresVerifier(connection).read({"sql": "DELETE FROM notes"})
        finally:
            connection.close()
    assert seen.ok and seen.data["count"] == 1
    assert not refused.ok

    mail = DockerContainer("axllent/mailpit:latest")
    mail.with_exposed_ports(1025, 8025)
    mail.waiting_for(HttpWaitStrategy(8025, "/api/v1/info"))
    with mail:
        smtp_port = int(mail.get_exposed_port(1025))
        http_port = int(mail.get_exposed_port(8025))
        host = mail.get_container_host_ip()
        _send_smtp(host, smtp_port)
        observation = MailpitVerifier(f"http://{host}:{http_port}").read(
            {"to": "probe@example.com", "subject_contains": "ledger", "body_contains": "world read", "expect_count": 1}
        )
    assert observation.ok, observation.summary


def _send_smtp(host: str, port: int) -> None:
    import smtplib
    from email.message import EmailMessage

    message = EmailMessage()
    message["To"] = "probe@example.com"
    message["From"] = "a3p@example.com"
    message["Subject"] = "ledger note"
    message.set_content("world read")
    deadline = time.time() + 15
    last = ""
    while time.time() < deadline:
        try:
            with smtplib.SMTP(host, port, timeout=5) as smtp:
                smtp.send_message(message)
            return
        except OSError as exc:
            last = str(exc)
            time.sleep(0.2)
    raise RuntimeError(last)


def test_minio_s3_verifier(tmp_path: Path) -> None:
    binary = minio_binary()
    if binary is None:
        pytest.skip("MinIO server binary is not installed")
    from minio import Minio

    from a3p.world.http_api import S3Verifier

    port = _free_port()
    data = tmp_path / "minio"
    data.mkdir()
    env = os.environ.copy()
    env["MINIO_ROOT_USER"] = "a3prober"
    env["MINIO_ROOT_PASSWORD"] = "a3prober-secret"
    process = subprocess.Popen(
        [binary, "server", str(data), "--address", f"127.0.0.1:{port}"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/minio/health/live", timeout=0.5)
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise TimeoutError("MinIO did not become ready")
        client = Minio(f"127.0.0.1:{port}", access_key="a3prober", secret_key="a3prober-secret", secure=False)
        client.make_bucket("probe")
        payload = b"sealed-object"
        client.put_object("probe", "note.txt", io.BytesIO(payload), length=len(payload))
        client.set_bucket_policy(
            "probe",
            json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": ["*"]},
                            "Action": ["s3:GetObject", "s3:ListBucket"],
                            "Resource": ["arn:aws:s3:::probe", "arn:aws:s3:::probe/*"],
                        }
                    ],
                }
            ),
        )
        verifier = S3Verifier(f"http://127.0.0.1:{port}")
        digest = hashlib.sha256(payload).hexdigest()
        seen = verifier.read({"bucket": "probe", "key": "note.txt", "sha256": digest})
        listed = verifier.read({"bucket": "probe", "expect_key": "note.txt"})
    finally:
        process.terminate()
        process.wait(timeout=5)
    assert seen.ok, seen.summary
    assert listed.ok, listed.summary


def test_openai_agents_and_crewai_against_a_mock() -> None:
    pytest.importorskip("agents")
    pytest.importorskip("crewai")
    from openai import AsyncOpenAI

    from a3p.adapters.crewai_agent import CrewAIAdapter, crew_runner
    from a3p.adapters.openai_agents import OpenAIAgentsAdapter, sdk_runner

    port = _free_port()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            self.rfile.read(length)
            payload = {
                "id": "mock",
                "object": "chat.completion",
                "model": "mock",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "pong"}, "finish_reason": "stop"}],
            }
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        from agents import Agent, Runner, set_tracing_disabled
        from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

        set_tracing_disabled(True)
        model = OpenAIChatCompletionsModel(
            model="mock",
            openai_client=AsyncOpenAI(base_url=f"http://127.0.0.1:{port}/v1", api_key="test"),
        )
        agent = Agent(name="probe", instructions="Reply with the single word pong.", model=model)
        direct = Runner.run_sync(agent, "ping")
        adapted = OpenAIAgentsAdapter(sdk_runner(agent)).run(task="ping", system="ignored", tools=[])
        from crewai import LLM, Crew, Task
        from crewai import Agent as CrewAgent

        llm = LLM(model="openai/gpt-4o-mini", base_url=f"http://127.0.0.1:{port}/v1", api_key="test", temperature=0)
        worker = CrewAgent(role="probe", goal="say pong", backstory="fixture", llm=llm, verbose=False)
        task = Task(description="Reply with pong", expected_output="pong", agent=worker)
        crew = Crew(agents=[worker], tasks=[task], verbose=False)
        wrapped = crew_runner(crew)
        crew_result = CrewAIAdapter(crew).run(task="ping", system="", tools=[])
    finally:
        server.shutdown()
    assert "pong" in str(direct.final_output)
    assert adapted.final_text == "pong"
    assert isinstance(wrapped, CrewAIAdapter)
    assert "pong" in crew_result.final_text.lower()
