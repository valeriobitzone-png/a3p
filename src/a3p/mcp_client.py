"""Minimal MCP client over HTTP JSON-RPC. Enough to list and call tools."""

from __future__ import annotations

from typing import Any

import httpx


class McpError(RuntimeError):
    pass


class McpHttpClient:
    def __init__(self, url: str, *, client: httpx.Client | None = None) -> None:
        self.url = url
        self.client = client
        self._seq = 0

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._seq += 1
        payload = {"jsonrpc": "2.0", "id": self._seq, "method": method, "params": params or {}}
        try:
            if self.client is not None:
                response = self.client.post(self.url, json=payload)
            else:
                response = httpx.post(self.url, json=payload, timeout=20.0)
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise McpError(f"{type(exc).__name__}: {exc}") from exc
        if not isinstance(body, dict):
            raise McpError("MCP response was not an object")
        if body.get("error"):
            raise McpError(str(body["error"]))
        return body.get("result")

    def list_tools(self) -> list[dict[str, Any]]:
        result = self.request("tools/list")
        if not isinstance(result, dict):
            raise McpError("tools/list result was not an object")
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise McpError("tools/list did not return tools")
        return [item for item in tools if isinstance(item, dict)]

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})
