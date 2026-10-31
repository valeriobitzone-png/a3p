"""LangGraph tool loop driven by an OpenAI-compatible chat model."""

from __future__ import annotations

import json
from typing import Any, cast

import httpx

from a3p.adapters.openai_chat import _schema, chat_body, replay_message, tool_result_message
from a3p.models import AgentResult, BoundTool, ToolCall
from a3p.sandbox import invoke_tool


class LangGraphModelAdapter:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "ollama",
        *,
        timeout: float = 60.0,
        seed: int | None = None,
        proxy: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.seed = seed
        self.proxy = proxy
        self.name = f"langgraph-model:{model}"

    def run(
        self,
        *,
        task: str,
        system: str,
        tools: list[BoundTool],
        max_turns: int = 6,
        followups: list[str] | None = None,
    ) -> AgentResult:
        from typing import TypedDict

        from langgraph.graph import END, START, StateGraph

        handlers = {tool.public.name: tool.handler for tool in tools}
        schemas = [_schema(tool.public) for tool in tools]
        base_url = self.base_url
        model = self.model
        api_key = self.api_key
        timeout = self.timeout
        seed = self.seed
        proxy = self.proxy

        class State(TypedDict, total=False):
            messages: list
            final_text: str
            calls: list
            steps: int

        def agent_node(state: Any) -> dict[str, Any]:
            if state.get("steps", 0) >= max_turns:
                return {"final_text": "Stopped: tool-turn limit reached before a final answer."}
            payload = chat_body(
                model=model,
                messages=list(state.get("messages") or []),
                schemas=schemas,
                seed=seed,
                base_url=base_url,
            )
            response = httpx.post(
                base_url + "/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
                proxy=proxy,
            )
            response.raise_for_status()
            message = response.json()["choices"][0]["message"]
            stored = replay_message(message if isinstance(message, dict) else {})
            messages = list(state["messages"]) + [stored]
            tool_calls = stored.get("tool_calls") or []
            if not tool_calls:
                return {"messages": messages, "final_text": stored.get("content") or ""}
            return {"messages": messages, "pending": tool_calls}

        def tool_node(state: Any) -> dict[str, Any]:
            messages = list(state.get("messages") or [])
            calls = list(state.get("calls") or [])
            pending = messages[-1].get("tool_calls") or []
            for call in pending:
                fn = call["function"]
                raw = fn.get("arguments") or "{}"
                try:
                    arguments = json.loads(raw) if isinstance(raw, str) else dict(raw)
                except json.JSONDecodeError:
                    arguments = {}
                handler = handlers.get(fn["name"])
                result = invoke_tool(handler, arguments) if handler else {"error": f"unknown tool {fn['name']}"}
                calls.append({"name": fn["name"], "arguments": arguments, "result": result})
                messages.append(tool_result_message(str(call.get("id") or fn["name"]), result))
            return {"messages": messages, "calls": calls, "steps": state.get("steps", 0) + 1}

        def route(state: Any) -> str:
            if state.get("final_text"):
                return END
            last = (state.get("messages") or [{}])[-1]
            if last.get("tool_calls"):
                return "tools"
            return END

        graph = StateGraph(State)
        graph.add_node("agent", agent_node)
        graph.add_node("tools", tool_node)
        graph.add_edge(START, "agent")
        graph.add_conditional_edges("agent", route, {"tools": "tools", END: END})
        graph.add_edge("tools", "agent")
        compiled = graph.compile()

        messages: list[dict] = [
            {"role": "system", "content": system},
            {"role": "user", "content": task},
        ]
        calls: list[dict] = []
        final_text = ""
        for index, segment in enumerate([task, *(followups or [])]):
            if index:
                messages.append({"role": "user", "content": segment})
            final = cast(dict[str, Any], compiled.invoke({"messages": messages, "calls": calls, "steps": 0, "final_text": ""}))  # type: ignore[call-overload]
            messages = list(final.get("messages") or messages)
            calls = list(final.get("calls") or calls)
            final_text = final.get("final_text") or final_text
        return AgentResult(
            final_text,
            [ToolCall(item["name"], item.get("arguments") or {}, item.get("result")) for item in calls],
        )
