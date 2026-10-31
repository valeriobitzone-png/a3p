"""Run a compiled LangGraph (or any object with ``invoke``) as a probe target."""

from __future__ import annotations

from typing import Any

from a3p.models import AgentResult, BoundTool, ToolCall


class CompiledGraphAdapter:
    def __init__(self, graph: Any, *, name: str = "langgraph-compiled") -> None:
        self.graph = graph
        self.name = name

    def run(
        self,
        *,
        task: str,
        system: str,
        tools: list[BoundTool],
        max_turns: int = 6,
        followups: list[str] | None = None,
    ) -> AgentResult:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": task}]
        for item in followups or []:
            messages.append({"role": "user", "content": item})
        state = self.graph.invoke({"messages": messages, "tools": [tool.public.name for tool in tools], "max_turns": max_turns})
        if not isinstance(state, dict):
            return AgentResult(str(state), [])
        text = str(state.get("final_text") or state.get("output") or "")
        calls: list[ToolCall] = []
        for item in state.get("tool_calls") or []:
            if isinstance(item, dict):
                calls.append(ToolCall(str(item.get("name") or ""), dict(item.get("arguments") or {}), item.get("result")))
        return AgentResult(text, calls)
