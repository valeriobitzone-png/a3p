"""Adapter for a CrewAI-shaped crew.

CrewAI is not a dependency. Pass an object with ``kickoff()``, or use
``crew_runner`` when the ``crewai`` package is installed.
"""

from __future__ import annotations

from typing import Any

from a3p.models import AgentResult, BoundTool, ToolCall


def _from_kickoff(result: Any) -> AgentResult:
    if isinstance(result, str):
        return AgentResult(result, [])
    text = str(getattr(result, "raw", None) or getattr(result, "final_output", None) or result)
    calls: list[ToolCall] = []
    tasks = getattr(result, "tasks_output", None) or []
    for task in tasks:
        for item in getattr(task, "tool_calls", None) or []:
            if isinstance(item, dict):
                calls.append(ToolCall(str(item.get("name") or ""), dict(item.get("arguments") or {}), item.get("result")))
    return AgentResult(text, calls)


class CrewAIAdapter:
    def __init__(self, crew: Any, *, name: str = "crewai") -> None:
        self.crew = crew
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
        del system, tools, max_turns
        kickoff = getattr(self.crew, "kickoff", None)
        if kickoff is None:
            raise RuntimeError("crew has no kickoff(). This adapter does not import CrewAI itself.")
        inputs = {"task": task, "followups": list(followups or [])}
        try:
            result = kickoff(inputs=inputs)
        except TypeError:
            result = kickoff()
        return _from_kickoff(result)


def crew_runner(crew: Any) -> CrewAIAdapter:
    try:
        import crewai  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "CrewAI is not installed. Pass an object with kickoff() to CrewAIAdapter, "
            "or install crewai in the environment that runs the probe."
        ) from exc
    return CrewAIAdapter(crew)
