"""A real LangGraph tool loop. The demo policies stand in for the chat model.

The graph is the usual agent → tools → agent cycle. State stays JSON-serializable.
Handlers live in the closure, not in the checkpointed state.
"""

from __future__ import annotations

from typing import Any

from a3p.models import AgentResult, BoundTool, ToolCall
from a3p.policy import StepCall, StepFinal, render_careful, render_vulnerable, step


class LangGraphAdapter:
    def __init__(self, policy: str = "vulnerable") -> None:
        if policy not in {"vulnerable", "careful"}:
            raise ValueError(f"unknown policy {policy!r}")
        self.policy = policy
        self.name = f"langgraph:{policy}"
        self._cautious = policy == "careful"

    def graph_node_names(self) -> list[str]:
        compiled = self._compile([], {})
        graph = compiled.get_graph()
        return sorted(node for node in graph.nodes if node not in {"__start__", "__end__"})

    def run(
        self,
        *,
        task: str,
        system: str,
        tools: list[BoundTool],
        max_turns: int = 6,
        followups: list[str] | None = None,
    ) -> AgentResult:
        handlers = {tool.public.name: tool.handler for tool in tools}
        public = [tool.public for tool in tools]
        compiled = self._compile(public, handlers, max_turns=max_turns)
        observations: list[dict] = []
        final_text = ""
        for segment in [task, *(followups or [])]:
            final = compiled.invoke(
                {
                    "task": segment,
                    "system": system,
                    "observations": observations,
                    "final_text": "",
                    "action": {},
                    "steps": 0,
                }
            )
            observations = list(final.get("observations") or [])
            final_text = final.get("final_text") or final_text
        calls = [
            ToolCall(item["name"], item.get("arguments") or {}, item.get("result"))
            for item in observations
        ]
        return AgentResult(final_text, calls)

    def _compile(self, public: list[Any], handlers: dict[str, Any], max_turns: int = 6) -> Any:
        from typing import TypedDict

        from langgraph.graph import END, START, StateGraph

        cautious = self._cautious

        class State(TypedDict, total=False):
            task: str
            system: str
            observations: list
            final_text: str
            action: dict
            steps: int

        def agent_node(state: Any) -> dict[str, Any]:
            observations = [
                ToolCall(item["name"], item.get("arguments") or {}, item.get("result"))
                for item in state.get("observations") or []
            ]
            if state.get("steps", 0) >= max_turns:
                text = (
                    render_careful(state["task"], state["system"], observations)
                    if cautious
                    else render_vulnerable(state["task"], state["system"], observations)
                )
                return {"final_text": text, "action": {"type": "final"}}
            decision = step(
                state["task"],
                state["system"],
                public,
                observations,
                cautious=cautious,
            )
            if isinstance(decision, StepFinal):
                return {"final_text": decision.text, "action": {"type": "final"}}
            assert isinstance(decision, StepCall)
            return {
                "action": {
                    "type": "tool",
                    "name": decision.name,
                    "arguments": decision.arguments,
                }
            }

        def tool_node(state: Any) -> dict[str, Any]:
            action: dict[str, Any] = state.get("action") or {}
            name = str(action.get("name") or "")
            arguments = action.get("arguments") or {}
            from a3p.sandbox import invoke_tool

            handler = handlers.get(name)
            result = invoke_tool(handler, arguments) if handler else {"error": f"unknown tool {name}"}
            observations = list(state.get("observations") or [])
            observations.append({"name": name, "arguments": arguments, "result": result})
            return {"observations": observations, "steps": state.get("steps", 0) + 1}

        def route(state: Any) -> str:
            if state.get("final_text"):
                return END
            if (state.get("action") or {}).get("type") == "tool":
                return "tools"
            return END

        graph = StateGraph(State)
        graph.add_node("agent", agent_node)
        graph.add_node("tools", tool_node)
        graph.add_edge(START, "agent")
        graph.add_conditional_edges("agent", route, {"tools": "tools", END: END})
        graph.add_edge("tools", "agent")
        return graph.compile()
