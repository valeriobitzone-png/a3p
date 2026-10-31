"""Adapter for an OpenAI Agents SDK-shaped runner.

The Agents SDK is not a dependency. Pass a callable, or use ``sdk_runner``
when the ``agents`` package is installed in the operator's environment.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from a3p.models import AgentResult, BoundTool, ToolCall


def _calls(result: Any) -> list[ToolCall]:
    raw = getattr(result, "tool_calls", None)
    if raw is None and isinstance(result, dict):
        raw = result.get("tool_calls") or []
    calls: list[ToolCall] = []
    for item in raw or []:
        if isinstance(item, dict):
            calls.append(ToolCall(str(item.get("name") or ""), dict(item.get("arguments") or {}), item.get("result")))
        else:
            calls.append(
                ToolCall(
                    str(getattr(item, "name", "") or ""),
                    dict(getattr(item, "arguments", {}) or {}),
                    getattr(item, "result", None),
                )
            )
    return calls


def _text(result: Any) -> str:
    if isinstance(result, dict):
        return str(result.get("final_output") or result.get("final_text") or "")
    return str(getattr(result, "final_output", None) or getattr(result, "final_text", "") or "")


class OpenAIAgentsAdapter:
    def __init__(self, runner: Callable[[str, str], Any], *, name: str = "openai-agents") -> None:
        self.runner = runner
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
        del tools, max_turns
        prompt = task if not followups else task + "\n" + "\n".join(followups)
        result = self.runner(prompt, system)
        return AgentResult(_text(result), _calls(result))


def sdk_runner(agent: Any) -> Callable[[str, str], Any]:
    """Return a runner that calls ``agents.Runner.run_sync`` if that package is installed."""

    def run(task: str, system: str) -> Any:
        del system
        try:
            from agents import Runner
        except ImportError as exc:
            raise RuntimeError(
                "The OpenAI Agents SDK is not installed. Pass a runner callable to OpenAIAgentsAdapter, "
                "or install the agents package in the environment that runs the probe."
            ) from exc
        return Runner.run_sync(agent, task)

    return run
