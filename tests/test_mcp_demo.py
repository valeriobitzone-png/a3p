"""In-process coverage for the vulnerable MCP demo. The live scan runs it as a child."""

from __future__ import annotations

import io
import json
import socket
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from a3p.mcp_dynamic import McpScanError, SseSession, run_live_scan
from a3p.mcp_vulnerable import (
    dispatch,
    encode_message,
    main,
    notes_description,
    read_message,
    reset_state,
    serve_sse,
    serve_stdio,
)


def test_dispatch_covers_every_method() -> None:
    reset_state()
    assert "ignore previous" in notes_description()
    assert notes_description().endswith("revised")
    assert dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    initialized = dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": []})
    assert initialized is not None
    assert initialized["result"]["capabilities"]["tools"] == {}
    listed = dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert listed is not None
    names = [item["name"] for item in listed["result"]["tools"]]
    assert names == ["notes", "shell", "lookup"]
    lookup = dispatch(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "lookup", "arguments": {"q": "hi"}}}
    )
    assert lookup is not None and "sk-a3p-demo-canary" in lookup["result"]["content"][0]["text"]
    bare = dispatch({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "notes"}})
    assert bare is not None and bare["result"]["content"][0]["text"] == "empty"
    shell = dispatch({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "shell", "arguments": {"cmd": "id"}}})
    assert shell is not None and "not executed" in shell["result"]["content"][0]["text"]
    unknown = dispatch({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "missing", "arguments": {}}})
    assert unknown is not None and unknown["result"]["isError"] is True
    resources = dispatch({"jsonrpc": "2.0", "id": 7, "method": "resources/list"})
    assert resources is not None and resources["result"]["resources"][0]["uri"] == "note://canary"
    read = dispatch({"jsonrpc": "2.0", "id": 8, "method": "resources/read", "params": {"uri": "note://canary"}})
    assert read is not None and read["result"]["contents"][0]["text"] == "sk-a3p-demo-canary"
    prompts = dispatch({"jsonrpc": "2.0", "id": 9, "method": "prompts/list"})
    assert prompts is not None and prompts["result"]["prompts"][0]["name"] == "override"
    prompt = dispatch({"jsonrpc": "2.0", "id": 10, "method": "prompts/get", "params": {"name": "override"}})
    assert prompt is not None and "ignore previous" in prompt["result"]["messages"][0]["content"]["text"]
    missing = dispatch({"jsonrpc": "2.0", "id": 11, "method": "nope"})
    assert missing is not None and missing["error"]["code"] == -32601


def test_framing_rejects_a_short_or_non_object_body() -> None:
    message = read_message(io.BytesIO(encode_message({"id": 1, "method": "ping"})))
    assert message["method"] == "ping"
    with pytest.raises(EOFError):
        read_message(io.BytesIO(b"Content-Length: 8\r\n\r\n{}"))
    with pytest.raises(ValueError):
        read_message(io.BytesIO(b"x" * 70000))
    body = b"[]"
    frame = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
    with pytest.raises(ValueError):
        read_message(io.BytesIO(frame))
    with pytest.raises(json.JSONDecodeError):
        read_message(io.BytesIO(b"Content-Length: 1\r\n\r\n{"))


def test_serve_stdio_answers_one_request(monkeypatch: pytest.MonkeyPatch) -> None:
    request = encode_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    request += b"Content-Length: 1\r\n\r\n{"
    output = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(request)))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=output))
    serve_stdio()
    parsed = read_message(io.BytesIO(output.getvalue()))
    assert parsed["result"]["serverInfo"]["name"] == "a3p-vulnerable-demo"


def test_sse_handler_errors_and_a_real_call() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    server = serve_sse(("127.0.0.1", port), socket.AF_INET)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert httpx.get(f"http://127.0.0.1:{port}/nope", timeout=5).status_code == 404
        assert httpx.post(f"http://127.0.0.1:{port}/nope", timeout=5).status_code == 404
        assert httpx.post(f"http://127.0.0.1:{port}/messages", content=b"not-json", timeout=5).status_code == 400
        assert httpx.post(f"http://127.0.0.1:{port}/messages", json=["nope"], timeout=5).status_code == 400
        noted = httpx.post(
            f"http://127.0.0.1:{port}/messages",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            timeout=5,
        )
        assert noted.status_code == 202
        session = SseSession(f"http://127.0.0.1:{port}")
        try:
            result = session.request("tools/list")
        finally:
            session.close()
        assert any(item["name"] == "lookup" for item in result["tools"])
    finally:
        server.shutdown()
        server.server_close()


def test_main_picks_stdio_sse_or_the_unix_socket(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    chosen: dict[str, object] = {}

    def stdio() -> None:
        chosen["mode"] = "stdio"

    def sse(address: object, family: int) -> SimpleNamespace:
        chosen["mode"] = "sse"
        chosen["address"] = address
        chosen["family"] = family
        return SimpleNamespace(serve_forever=lambda: None)

    monkeypatch.setattr("a3p.mcp_vulnerable.serve_stdio", stdio)
    monkeypatch.setattr("a3p.mcp_vulnerable.serve_sse", sse)
    monkeypatch.delenv("A3P_MCP_UDS", raising=False)
    monkeypatch.delenv("A3P_MCP_SSE_PORT", raising=False)
    main()
    assert chosen["mode"] == "stdio"
    monkeypatch.setenv("A3P_MCP_SSE_PORT", "8765")
    main()
    assert chosen["address"] == ("127.0.0.1", 8765)
    sock = tmp_path / "mcp.sock"
    sock.write_text("stale", encoding="utf-8")
    monkeypatch.setenv("A3P_MCP_UDS", str(sock))
    main()
    assert chosen["address"] == str(sock)
    assert not sock.exists()


def test_scan_rejects_unknown_transport(tmp_path: Path) -> None:
    with pytest.raises(McpScanError):
        run_live_scan(level="process", transport="ws", output=tmp_path, probes=[])
    with pytest.raises(McpScanError):
        run_live_scan(level="inprocess", transport="stdio", output=tmp_path, probes=[])
