"""Run a probe against an in-process policy callable."""

from __future__ import annotations

from a3p.models import AgentResult, BoundTool
from a3p.policy import react_loop


class CallableAdapter:
    def __init__(self, policy: str = "vulnerable") -> None:
        if policy not in {"vulnerable", "careful"}:
            raise ValueError(f"unknown policy {policy!r}")
        self.policy = policy
        self.name = f"callable:{policy}"

    def run(
        self,
        *,
        task: str,
        system: str,
        tools: list[BoundTool],
        max_turns: int = 6,
        followups: list[str] | None = None,
    ) -> AgentResult:
        return react_loop(self.policy == "careful", task, system, tools, max_turns, followups)
