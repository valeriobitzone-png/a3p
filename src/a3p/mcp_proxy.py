"""Live MCP proxy. Pins tool descriptions, blocks rug-pulls, enforces an allow-list.

Upstream can be a stdio process or a streamable HTTP endpoint. Downstream is
the same pair of transports. A pin is the sha256 from ``mcp_static.tool_fingerprint``.
The first observation pins a tool that has no pin yet. A later change is a rug-pull
and the tool is not forwarded. This is not a Sigstore signature and not a promise
that an allowed tool is safe.
"""

from __future__ import annotations

import asyncio
from typing import Any

from a3p.mcp_static import tool_fingerprint


class ProxyRefusal(RuntimeError):
    pass


class ToolGate:
    def __init__(self, pins: dict[str, str] | None = None, allow: set[str] | None = None) -> None:
        self.pins = dict(pins or {})
        self.allow = None if allow is None else set(allow)
        self.blocked: set[str] = set()
        self.findings: list[dict[str, str]] = []

    def observe(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        visible: list[dict[str, Any]] = []
        for tool in tools:
            name = str(tool.get("name") or "")
            if not name:
                continue
            if self.allow is not None and name not in self.allow:
                self.blocked.add(name)
                self.findings.append({"kind": "denied", "name": name, "summary": f"{name} is not on the allow-list"})
                continue
            digest = tool_fingerprint(tool)
            pinned = self.pins.get(name)
            if pinned is None:
                self.pins[name] = digest
                self.findings.append({"kind": "pinned", "name": name, "summary": f"pinned {name}", "sha256": digest})
                visible.append(tool)
                continue
            if pinned != digest:
                self.blocked.add(name)
                self.findings.append(
                    {
                        "kind": "rug-pull",
                        "name": name,
                        "summary": f"description hash changed for {name}",
                        "sha256": digest,
                        "pinned": pinned,
                    }
                )
                continue
            visible.append(tool)
        return visible

    def allow_call(self, name: str) -> str | None:
        if self.allow is not None and name not in self.allow:
            return f"{name} is not on the allow-list"
        if name in self.blocked:
            return f"{name} is blocked after a pin mismatch"
        if name not in self.pins:
            return f"{name} has not been pinned; list tools first"
        return None


def tool_record(tool: Any) -> dict[str, Any]:
    if hasattr(tool, "model_dump"):
        raw = tool.model_dump(by_alias=True, exclude_none=True)
    elif isinstance(tool, dict):
        raw = tool
    else:
        raw = {"name": getattr(tool, "name", ""), "description": getattr(tool, "description", "")}
    schema = raw.get("inputSchema") or raw.get("input_schema") or raw.get("parameters") or {}
    if not isinstance(schema, dict):
        schema = {}
    return {
        "name": str(raw.get("name") or ""),
        "description": str(raw.get("description") or ""),
        "inputSchema": schema,
    }


class LiveProxy:
    """Forward list and call through an already initialized MCP client session."""

    def __init__(self, session: Any, gate: ToolGate) -> None:
        self.session = session
        self.gate = gate

    async def list_tools(self) -> list[dict[str, Any]]:
        result = await self.session.list_tools()
        records = [tool_record(item) for item in result.tools]
        return self.gate.observe(records)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        reason = self.gate.allow_call(name)
        if reason:
            raise ProxyRefusal(reason)
        return await self.session.call_tool(name, arguments or {})


def _downstream(proxy: LiveProxy) -> Any:
    import mcp.types as types
    from mcp.server.lowlevel import Server

    async def on_list_tools(ctx: Any, params: Any) -> Any:
        del ctx, params
        visible = await proxy.list_tools()
        tools = [
            types.Tool.model_validate(
                {"name": item["name"], "description": item["description"], "inputSchema": item["inputSchema"]}
            )
            for item in visible
        ]
        return types.ListToolsResult(tools=tools)

    async def on_call_tool(ctx: Any, params: Any) -> Any:
        del ctx
        name = str(params.name)
        arguments = dict(params.arguments or {})
        reason = proxy.gate.allow_call(name)
        if reason:
            return types.CallToolResult(content=[types.TextContent(type="text", text=reason)], is_error=True)
        try:
            result = await proxy.call_tool(name, arguments)
        except ProxyRefusal as exc:
            return types.CallToolResult(content=[types.TextContent(type="text", text=str(exc))], is_error=True)
        return result

    return Server("a3p-mcp-proxy", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def _upstream_session(
    stack: Any,
    *,
    command: list[str] | None,
    url: str | None,
    env: dict[str, str] | None = None,
) -> Any:
    from mcp import ClientSession

    if command:
        from mcp.client.stdio import StdioServerParameters, stdio_client

        streams = await stack.enter_async_context(
            stdio_client(StdioServerParameters(command=command[0], args=command[1:], env=env))
        )
    elif url:
        from mcp.client.streamable_http import streamable_http_client

        streams = await stack.enter_async_context(streamable_http_client(url))
    else:
        raise ProxyRefusal("proxy needs an upstream command or URL")
    session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
    await session.initialize()
    return session


async def serve_stdio(proxy: LiveProxy) -> None:
    from mcp.server.stdio import stdio_server

    server = _downstream(proxy)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


async def serve_http(proxy: LiveProxy, host: str, port: int) -> None:
    import uvicorn

    server = _downstream(proxy)
    app = server.streamable_http_app(host=host, json_response=True, stateless_http=True)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    running = uvicorn.Server(config)
    await running.serve()


async def run_proxy(
    *,
    upstream_command: list[str] | None = None,
    upstream_url: str | None = None,
    downstream: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8768,
    pins: dict[str, str] | None = None,
    allow: set[str] | None = None,
    upstream_env: dict[str, str] | None = None,
) -> None:
    from contextlib import AsyncExitStack

    async with AsyncExitStack() as stack:
        session = await _upstream_session(
            stack,
            command=upstream_command,
            url=upstream_url,
            env=upstream_env,
        )
        proxy = LiveProxy(session, ToolGate(pins, allow))
        if downstream == "stdio":
            await serve_stdio(proxy)
            return
        if downstream == "streamable-http":
            await serve_http(proxy, host, port)
            return
        raise ProxyRefusal(f"unknown downstream transport {downstream}")


def run_proxy_sync(**kwargs: Any) -> None:
    asyncio.run(run_proxy(**kwargs))
