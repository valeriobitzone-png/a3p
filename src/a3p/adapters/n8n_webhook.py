"""n8n-shaped webhook target.

The JSON export is a real n8n workflow document (webhook → AI agent →
respond). The runner understands that shape only. It is not an n8n engine:
Code nodes, credentials, and other node types are not executed.

In HTTP mode the probe POSTs the task and plays tool results back, which is
how an audit harness sits in front of a webhook it does not own.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import httpx

from a3p.models import AgentResult, BoundTool, PublicTool, ToolCall
from a3p.policy import StepCall, StepFinal, step


def load_workflow(path: str | Path) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a JSON object")
    nodes = document.get("nodes") or []
    types = [node.get("type", "") for node in nodes]
    if not any("webhook" in item for item in types):
        raise ValueError(f"{path} has no webhook node")
    if not any("agent" in item for item in types):
        raise ValueError(f"{path} has no agent node")
    return document


def decide(
    task: str,
    system: str,
    tools: list[PublicTool],
    observations: list[ToolCall],
    *,
    cautious: bool,
) -> dict:
    decision = step(task, system, tools, observations, cautious=cautious)
    if isinstance(decision, StepFinal):
        return {"action": "final", "text": decision.text}
    assert isinstance(decision, StepCall)
    return {"action": "tool", "name": decision.name, "arguments": decision.arguments}


class N8nWebhookServer:
    """Local webhook that serves one vulnerable (or careful) workflow."""

    def __init__(self, workflow_path: str | Path, policy: str = "vulnerable") -> None:
        self.workflow = load_workflow(workflow_path)
        self.policy = policy
        self._cautious = policy == "careful"
        harness = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw.decode("utf-8") or "{}")
                except json.JSONDecodeError:
                    self._send(400, {"error": "invalid json"})
                    return
                if self.path.rstrip("/") != "/webhook/support-agent":
                    self._send(404, {"error": "not found"})
                    return
                publics = [
                    PublicTool(
                        name=item["name"],
                        description=item.get("description") or "",
                        parameters=item.get("parameters") or {"type": "object", "properties": {}},
                        annotations=item.get("annotations") or {},
                    )
                    for item in body.get("tools") or []
                ]
                observations = [
                    ToolCall(item["name"], item.get("arguments") or {}, item.get("result"))
                    for item in body.get("observations") or []
                ]
                payload = decide(
                    body.get("task") or "",
                    body.get("system") or "",
                    publics,
                    observations,
                    cautious=harness._cautious,
                )
                payload["workflow"] = harness.workflow.get("name")
                self._send(200, payload)

            def _send(self, status: int, payload: dict) -> None:
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        if isinstance(host, bytes):
            host = host.decode()
        return f"http://{host}:{port}/webhook/support-agent"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class N8nAdapter:
    def __init__(
        self,
        workflow_path: str | Path,
        policy: str = "vulnerable",
        *,
        mode: str = "inprocess",
        webhook_url: str | None = None,
        server: N8nWebhookServer | None = None,
    ) -> None:
        if policy not in {"vulnerable", "careful"}:
            raise ValueError(f"unknown policy {policy!r}")
        self.workflow_path = str(workflow_path)
        self.workflow = load_workflow(workflow_path)
        self.policy = policy
        self.mode = mode
        self.webhook_url = webhook_url
        self._server = server
        self.name = f"n8n:{mode}:{policy}"

    def run(
        self,
        *,
        task: str,
        system: str,
        tools: list[BoundTool],
        max_turns: int = 6,
        followups: list[str] | None = None,
    ) -> AgentResult:
        if self.mode == "http":
            return self._run_http(task, system, tools, max_turns, followups)
        return self._run_inprocess(task, system, tools, max_turns, followups)

    def _run_inprocess(
        self,
        task: str,
        system: str,
        tools: list[BoundTool],
        max_turns: int,
        followups: list[str] | None = None,
    ) -> AgentResult:
        from a3p.sandbox import invoke_tool
        public = [tool.public for tool in tools]
        handlers = {tool.public.name: tool.handler for tool in tools}
        observations: list[ToolCall] = []
        cautious = self.policy == "careful"
        final = ""
        for segment in [task, *(followups or [])]:
            for _ in range(max_turns):
                payload = decide(segment, system, public, observations, cautious=cautious)
                if payload["action"] == "final":
                    final = payload["text"]
                    break
                name = payload["name"]
                arguments = payload.get("arguments") or {}
                handler = handlers.get(name)
                result = invoke_tool(handler, arguments) if handler else {"error": f"unknown tool {name}"}
                observations.append(ToolCall(name, arguments, result))
            else:
                final = "Stopped: tool-turn limit reached before a final answer."
        return AgentResult(final, observations)

    def _run_http(
        self,
        task: str,
        system: str,
        tools: list[BoundTool],
        max_turns: int,
        followups: list[str] | None = None,
    ) -> AgentResult:
        from a3p.sandbox import invoke_tool
        url = self.webhook_url or (self._server.url if self._server else None)
        if not url:
            raise RuntimeError("n8n http mode needs a webhook_url or a running server")
        handlers = {tool.public.name: tool.handler for tool in tools}
        observations: list[dict] = []
        calls: list[ToolCall] = []
        public = [
            {
                "name": tool.public.name,
                "description": tool.public.description,
                "parameters": tool.public.parameters,
                "annotations": tool.public.annotations,
            }
            for tool in tools
        ]
        final = ""
        with httpx.Client(timeout=10.0) as client:
            for segment in [task, *(followups or [])]:
                for _ in range(max_turns):
                    response = client.post(
                        url,
                        json={
                            "task": segment,
                            "system": system,
                            "tools": public,
                            "observations": observations,
                        },
                    )
                    response.raise_for_status()
                    payload = response.json()
                    if payload.get("action") == "final":
                        final = payload.get("text") or ""
                        break
                    name = payload["name"]
                    arguments = payload.get("arguments") or {}
                    handler = handlers.get(name)
                    result = invoke_tool(handler, arguments) if handler else {"error": f"unknown tool {name}"}
                    calls.append(ToolCall(name, arguments, result))
                    observations.append({"name": name, "arguments": arguments, "result": result})
                else:
                    final = "Stopped: tool-turn limit reached before a final answer."
        return AgentResult(final, calls)
