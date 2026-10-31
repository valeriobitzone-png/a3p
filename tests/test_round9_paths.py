"""In-process paths for the proxy, Sigstore helpers, and their CLI commands."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a3p.attest import (
    PAYLOAD_TYPE,
    STATEMENT_TYPE,
    AttestationError,
    KeylessUnavailable,
    ambient_identity,
    pae,
    sign_keyless,
    sign_result,
    sign_statement,
    statement_for,
    verify_envelope,
    verify_keyless,
    verify_keyless_cli,
)
from a3p.cli import main
from a3p.mcp_proxy import (
    LiveProxy,
    ProxyRefusal,
    ToolGate,
    _downstream,
    _upstream_session,
    run_proxy,
    run_proxy_sync,
    serve_http,
    serve_stdio,
    tool_record,
)


def _document() -> dict[str, Any]:
    return statement_for("results.json", b"{}", {"statement": "assessed under A3P Method v1.0, level A3P-L0"})


def _public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def test_verify_envelope_rejects_malformed_cases() -> None:
    key = Ed25519PrivateKey.generate()
    payload = base64.b64encode(b"{}").decode("ascii")
    with pytest.raises(AttestationError, match="no signatures"):
        verify_envelope({"payloadType": PAYLOAD_TYPE, "payload": payload, "signatures": []})
    with pytest.raises(AttestationError, match="not an object"):
        verify_envelope({"payloadType": PAYLOAD_TYPE, "payload": payload, "signatures": ["nope"]})
    sealed = sign_statement({"_type": STATEMENT_TYPE, "predicate": {}}, key)
    with pytest.raises(AttestationError, match="pinned"):
        verify_envelope(sealed, public_key_hex="ab" * 32)
    sealed["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    with pytest.raises(AttestationError, match="rejected"):
        verify_envelope(sealed)
    raw = b"not-json"
    signed = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(raw).decode("ascii"),
        "signatures": [
            {
                "keyid": _public_hex(key),
                "sig": base64.b64encode(key.sign(pae(PAYLOAD_TYPE, raw))).decode("ascii"),
            }
        ],
    }
    with pytest.raises(AttestationError, match="not JSON"):
        verify_envelope(signed)
    wrong = sign_statement({"_type": "nope"}, key)
    with pytest.raises(AttestationError, match="Statement"):
        verify_envelope(wrong)


def test_ambient_identity_import_detect_and_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "sigstore.oidc", None)
    with pytest.raises(KeylessUnavailable, match="not installed"):
        ambient_identity()
    monkeypatch.undo()

    def broken() -> str:
        raise RuntimeError("metadata down")

    monkeypatch.setattr("sigstore.oidc.detect_credential", broken)
    with pytest.raises(KeylessUnavailable, match="Ambient OIDC"):
        ambient_identity()
    monkeypatch.setattr("sigstore.oidc.detect_credential", lambda: "")
    with pytest.raises(KeylessUnavailable, match="No ambient OIDC"):
        ambient_identity()


def test_sign_keyless_reports_fulcio_and_bundle_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    document = _document()
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(
        "a3p.attest.ambient_identity",
        lambda: SimpleNamespace(identity="user@example.com", issuer="https://issuer.example"),
    )

    def raise_keyless(payload: bytes, identity: object) -> object:
        raise KeylessUnavailable("token expired")

    monkeypatch.setattr("a3p.attest._production_sign", raise_keyless)
    with pytest.raises(KeylessUnavailable, match="expired"):
        sign_keyless(document)

    def raise_attest(payload: bytes, identity: object) -> object:
        raise AttestationError("policy")

    monkeypatch.setattr("a3p.attest._production_sign", raise_attest)
    with pytest.raises(AttestationError, match="policy"):
        sign_keyless(document)

    def raise_runtime(payload: bytes, identity: object) -> object:
        raise RuntimeError("fulcio down")

    monkeypatch.setattr("a3p.attest._production_sign", raise_runtime)
    with pytest.raises(AttestationError, match="Fulcio"):
        sign_keyless(document)
    with pytest.raises(AttestationError, match="Fulcio"):
        sign_result(document, key)

    class NotJson:
        def to_json(self) -> str:
            return "not-json"

    monkeypatch.setattr("a3p.attest._production_sign", lambda payload, identity: NotJson())
    with pytest.raises(AttestationError, match="not JSON"):
        sign_keyless(document)

    class NotObject:
        def to_json(self) -> str:
            return "[]"

    monkeypatch.setattr("a3p.attest._production_sign", lambda payload, identity: NotObject())
    with pytest.raises(AttestationError, match="not an object"):
        sign_keyless(document)


class _Bundle:
    def __init__(self) -> None:
        self.log_entry = SimpleNamespace(
            _inner=SimpleNamespace(
                inclusion_proof=SimpleNamespace(checkpoint="checkpoint"),
                log_index=4,
                integrated_time=8,
            )
        )

    @classmethod
    def from_json(cls, raw: str) -> _Bundle:
        if "reject-json" in raw:
            raise ValueError("bad bundle")
        bundle = cls()
        if "no-proof" in raw:
            bundle.log_entry._inner.inclusion_proof = None
        if "empty-proof" in raw:
            bundle.log_entry._inner.inclusion_proof = SimpleNamespace(checkpoint="")
        return bundle


class _Verifier:
    @staticmethod
    def production() -> _Verifier:
        return _Verifier()

    def verify_artifact(self, payload: bytes, bundle: object, policy: object) -> None:
        if getattr(policy, "_identity", "") == "reject-me":
            raise RuntimeError("policy")


def test_verify_keyless_requires_the_inclusion_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sigstore.models.Bundle", _Bundle)
    monkeypatch.setattr("sigstore.verify.Verifier", _Verifier)
    document = _document()
    checked = verify_keyless(
        document,
        {"bundle": {"marker": "ok"}},
        identity="user@example.com",
        issuer="https://issuer.example",
    )
    assert checked["logIndex"] == "4"
    flat = verify_keyless(document, {"marker": "flat"}, identity="user@example.com", issuer="https://issuer.example")
    assert flat["integratedTime"] == "8"
    with pytest.raises(AttestationError, match="rejected"):
        verify_keyless(document, "reject-json", identity="user@example.com", issuer="https://issuer.example")
    with pytest.raises(AttestationError, match="sigstore verify failed"):
        verify_keyless(document, {"marker": "ok"}, identity="reject-me", issuer="https://issuer.example")
    with pytest.raises(AttestationError, match="inclusion proof"):
        verify_keyless(document, "no-proof", identity="user@example.com", issuer="https://issuer.example")
    with pytest.raises(AttestationError, match="inclusion proof"):
        verify_keyless(document, "empty-proof", identity="user@example.com", issuer="https://issuer.example")


def test_verify_keyless_cli_reports_the_process(monkeypatch: pytest.MonkeyPatch) -> None:
    def ok(command: list[str], check: bool, capture_output: bool, text: bool) -> SimpleNamespace:
        assert "verify" in command
        return SimpleNamespace(returncode=0, stdout="verified\n", stderr="")

    monkeypatch.setattr("a3p.attest.subprocess.run", ok)
    assert verify_keyless_cli("a.json", "b.json", "user@example.com", "https://issuer.example") == "verified\n"

    def denied(command: list[str], check: bool, capture_output: bool, text: bool) -> SimpleNamespace:
        return SimpleNamespace(returncode=1, stdout="", stderr="denied")

    monkeypatch.setattr("a3p.attest.subprocess.run", denied)
    with pytest.raises(AttestationError, match="denied"):
        verify_keyless_cli("a.json", "b.json", "user@example.com", "https://issuer.example")

    def stdout_only(command: list[str], check: bool, capture_output: bool, text: bool) -> SimpleNamespace:
        return SimpleNamespace(returncode=1, stdout="no proof", stderr="")

    monkeypatch.setattr("a3p.attest.subprocess.run", stdout_only)
    with pytest.raises(AttestationError, match="no proof"):
        verify_keyless_cli("a.json", "b.json", "user@example.com", "https://issuer.example")

    def silent(command: list[str], check: bool, capture_output: bool, text: bool) -> SimpleNamespace:
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr("a3p.attest.subprocess.run", silent)
    with pytest.raises(AttestationError, match="sigstore verify failed"):
        verify_keyless_cli("a.json", "b.json", "user@example.com", "https://issuer.example")

    def missing(*args: object, **kwargs: object) -> SimpleNamespace:
        raise OSError("not on PATH")

    monkeypatch.setattr("a3p.attest.subprocess.run", missing)
    with pytest.raises(AttestationError, match="could not run"):
        verify_keyless_cli("a.json", "b.json", "user@example.com", "https://issuer.example")


def test_keyless_cli_success_and_refusals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    statement = tmp_path / "statement.json"
    statement.write_text("[]\n", encoding="utf-8")
    assert main(["sign-keyless", str(statement), "-o", str(tmp_path / "out.json")]) == 1
    statement.write_text(json.dumps(_document()), encoding="utf-8")

    def refused(document: dict[str, Any]) -> dict[str, Any]:
        raise AttestationError("fulcio refused")

    monkeypatch.setattr("a3p.attest.sign_keyless", refused)
    assert main(["sign-keyless", str(statement), "-o", str(tmp_path / "out.json")]) == 1
    monkeypatch.setattr("a3p.attest.sign_keyless", lambda document: {"mediaType": "bundle", "bundle": {"ok": True}})
    output = tmp_path / "out.json"
    assert main(["sign-keyless", str(statement), "-o", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["mediaType"] == "bundle"

    bundle = tmp_path / "bundle.json"
    statement.write_text("{", encoding="utf-8")
    bundle.write_text("{}", encoding="utf-8")
    assert main(["verify-sigstore", str(statement), str(bundle), "--identity", "a", "--issuer", "https://i.example"]) == 1
    statement.write_text("[]", encoding="utf-8")
    assert main(["verify-sigstore", str(statement), str(bundle), "--identity", "a", "--issuer", "https://i.example"]) == 1
    statement.write_text(json.dumps(_document()), encoding="utf-8")
    bundle.write_text(json.dumps({"bundle": {"marker": "nested"}}), encoding="utf-8")

    def checked(document: dict[str, Any], raw: dict[str, Any], *, identity: str, issuer: str) -> dict[str, str]:
        return {"logIndex": "9", "integratedTime": "1", "identity": identity, "issuer": issuer}

    monkeypatch.setattr("a3p.attest.verify_keyless", checked)
    monkeypatch.setattr("a3p.attest.verify_keyless_cli", lambda *args: "ok")
    assert main(["verify-sigstore", str(statement), str(bundle), "--identity", "a", "--issuer", "https://i.example"]) == 0
    bundle.write_text(json.dumps({"marker": "flat"}), encoding="utf-8")
    assert main(["verify-sigstore", str(statement), str(bundle), "--identity", "a", "--issuer", "https://i.example"]) == 0


def test_mcp_proxy_cli_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pin = tmp_path / "pins.json"
    pin.write_text("{", encoding="utf-8")
    assert main(["mcp-proxy", "--upstream-command", sys_executable(), "--pin", str(pin)]) == 1
    seen: list[dict[str, Any]] = []

    def capture(**kwargs: Any) -> None:
        seen.append(kwargs)

    monkeypatch.setattr("a3p.mcp_proxy.run_proxy_sync", capture)
    pin.write_text("[]", encoding="utf-8")
    assert main(["mcp-proxy", "--upstream-command", "python", "--pin", str(pin)]) == 0
    assert seen[-1]["pins"] == {}
    pin.write_text(json.dumps({"add": "abc"}), encoding="utf-8")
    assert (
        main(
            [
                "mcp-proxy",
                "--upstream-command",
                "python",
                "--pin",
                str(pin),
                "--allow",
                "add",
                "--upstream-env",
                "A3P_MCP_DESC_FILE=/tmp/desc",
            ]
        )
        == 0
    )
    assert seen[-1]["pins"] == {"add": "abc"}
    assert seen[-1]["allow"] == {"add"}
    assert seen[-1]["upstream_env"]["A3P_MCP_DESC_FILE"].endswith("desc")
    assert main(["mcp-proxy", "--upstream-command", "python", "--upstream-env", "NOEQUALS"]) == 2
    assert main(["mcp-proxy", "--upstream-command", "python", "--upstream-url", "http://127.0.0.1/mcp"]) == 2

    def refuse(**kwargs: Any) -> None:
        raise ProxyRefusal("no upstream")

    monkeypatch.setattr("a3p.mcp_proxy.run_proxy_sync", refuse)
    assert main(["mcp-proxy", "--upstream-url", "http://127.0.0.1/mcp"]) == 1

    def interrupted(**kwargs: Any) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("a3p.mcp_proxy.run_proxy_sync", interrupted)
    assert main(["mcp-proxy", "--upstream-url", "http://127.0.0.1/mcp"]) == 0


def sys_executable() -> str:
    import sys

    return sys.executable


class _CM:
    def __init__(self, value: object) -> None:
        self.value = value

    async def __aenter__(self) -> object:
        return self.value

    async def __aexit__(self, *exc: object) -> None:
        return None


class _DumpTool:
    def model_dump(self, by_alias: bool = True, exclude_none: bool = True) -> dict[str, Any]:
        return {"name": "add", "description": "Add two integers.", "inputSchema": {"type": "object"}}


class _BareTool:
    name = "bare"
    description = "plain"


def test_live_proxy_handlers_and_records() -> None:
    asyncio.run(_live_proxy_handlers())


async def _live_proxy_handlers() -> None:
    class Session:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, Any]]] = []

        async def list_tools(self) -> Any:
            return SimpleNamespace(
                tools=[
                    _DumpTool(),
                    {"name": "dict-tool", "description": "d", "input_schema": {"type": "object"}},
                    {"name": "params-tool", "description": "", "parameters": {"type": "object"}},
                    {"name": "bad-schema", "description": "b", "inputSchema": "nope"},
                    {"name": "", "description": "skip"},
                    _BareTool(),
                ]
            )

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
            self.calls.append((name, arguments))
            return "upstream-result"

    session = Session()
    proxy = LiveProxy(session, ToolGate(allow={"add", "dict-tool", "params-tool", "bad-schema", "bare"}))
    listed = await proxy.list_tools()
    assert [item["name"] for item in listed] == ["add", "dict-tool", "params-tool", "bad-schema", "bare"]
    assert tool_record(_DumpTool())["inputSchema"] == {"type": "object"}
    assert tool_record({"name": "bad-schema", "inputSchema": "nope"})["inputSchema"] == {}
    with pytest.raises(ProxyRefusal, match="allow-list"):
        await proxy.call_tool("secret", {})

    server = _downstream(proxy)
    list_handler = server._request_handlers["tools/list"].handler
    listed_result = await list_handler(None, None)
    assert [tool.name for tool in listed_result.tools] == ["add", "dict-tool", "params-tool", "bad-schema", "bare"]
    call_handler = server._request_handlers["tools/call"].handler
    assert await call_handler(None, SimpleNamespace(name="add", arguments={"a": 1})) == "upstream-result"
    assert await call_handler(None, SimpleNamespace(name="add", arguments=None)) == "upstream-result"
    assert session.calls[-1] == ("add", {})
    hidden = await call_handler(None, SimpleNamespace(name="secret", arguments={}))
    assert hidden.is_error

    async def refuse(name: str, arguments: dict[str, Any]) -> str:
        raise ProxyRefusal("pin moved")

    proxy.call_tool = refuse  # type: ignore[method-assign]
    blocked = await call_handler(None, SimpleNamespace(name="add", arguments={}))
    assert blocked.is_error
    assert "pin moved" in blocked.content[0].text

    fresh = LiveProxy(session, ToolGate())
    with pytest.raises(ProxyRefusal, match="pinned"):
        await fresh.call_tool("add", {})


def test_proxy_upstream_serve_and_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_stdio(params: Any) -> _CM:
        seen["command"] = params.command
        seen["env"] = params.env
        return _CM(("r", "w"))

    def fake_http(url: str) -> _CM:
        seen["url"] = url
        return _CM(("hr", "hw"))

    class Session:
        def __init__(self, read: object, write: object) -> None:
            self.read = read
            self.write = write

        async def __aenter__(self) -> Session:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def initialize(self) -> None:
            seen["init"] = True

    monkeypatch.setattr("mcp.client.stdio.stdio_client", fake_stdio)
    monkeypatch.setattr("mcp.client.streamable_http.streamable_http_client", fake_http)
    monkeypatch.setattr("mcp.ClientSession", Session)

    async def fake_run(self: Any, read: object, write: object, options: object) -> None:
        seen["stdio"] = (read, write)

    from mcp.server.lowlevel import Server

    monkeypatch.setattr(Server, "run", fake_run)

    class StdioCM:
        async def __aenter__(self) -> tuple[str, str]:
            return ("read", "write")

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr("mcp.server.stdio.stdio_server", lambda: StdioCM())

    class Uvicorn:
        def __init__(self, config: object) -> None:
            seen["config"] = config

        async def serve(self) -> None:
            seen["http"] = True

    monkeypatch.setattr("uvicorn.Server", Uvicorn)
    asyncio.run(_proxy_dispatch(seen))
    assert seen["command"] == "python"
    assert seen["url"] == "http://127.0.0.1:9/mcp"
    assert seen["stdio"] == ("read", "write")
    assert seen["http"] is True

    called: list[str] = []

    async def upstream(stack: object, *, command: list[str] | None, url: str | None, env: dict[str, str] | None) -> object:
        called.append(url or "stdio")
        return SimpleNamespace()

    async def as_stdio(proxy: LiveProxy) -> None:
        called.append("down-stdio")

    async def as_http(proxy: LiveProxy, host: str, port: int) -> None:
        called.append(f"{host}:{port}")

    monkeypatch.setattr("a3p.mcp_proxy._upstream_session", upstream)
    monkeypatch.setattr("a3p.mcp_proxy.serve_stdio", as_stdio)
    monkeypatch.setattr("a3p.mcp_proxy.serve_http", as_http)
    asyncio.run(run_proxy(upstream_command=["python"]))
    asyncio.run(run_proxy(upstream_url="http://127.0.0.1/mcp", downstream="streamable-http", host="127.0.0.1", port=9))
    with pytest.raises(ProxyRefusal, match="unknown downstream"):
        asyncio.run(run_proxy(upstream_command=["python"], downstream="carrier-pigeon"))
    assert "down-stdio" in called
    assert "127.0.0.1:9" in called

    async def marker(**kwargs: Any) -> None:
        seen["sync"] = kwargs["upstream_command"]

    monkeypatch.setattr("a3p.mcp_proxy.run_proxy", marker)
    run_proxy_sync(upstream_command=["sync"])
    assert seen["sync"] == ["sync"]


async def _proxy_dispatch(seen: dict[str, object]) -> None:
    from contextlib import AsyncExitStack

    async with AsyncExitStack() as stack:
        with pytest.raises(ProxyRefusal, match="upstream"):
            await _upstream_session(stack, command=None, url=None)
        session = await _upstream_session(stack, command=["python", "server.py"], url=None, env={"A": "b"})
        assert session.read == "r"
        assert seen["env"] == {"A": "b"}
        http = await _upstream_session(stack, command=None, url="http://127.0.0.1:9/mcp")
        assert http.read == "hr"
    proxy = LiveProxy(SimpleNamespace(), ToolGate())
    await serve_stdio(proxy)
    await serve_http(proxy, "127.0.0.1", 9)
