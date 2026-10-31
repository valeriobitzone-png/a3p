"""Shared data types for probes, agent turns, and findings."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Mapping:
    framework: str
    ref: str
    title: str


@dataclass(frozen=True)
class PublicTool:
    """What the agent is allowed to see. Probe expectations are not on this object."""

    name: str
    description: str
    parameters: dict[str, Any]
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class BoundTool:
    public: PublicTool
    handler: Callable[[dict[str, Any]], Any]


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    result: Any


@dataclass
class AgentResult:
    final_text: str
    tool_calls: list[ToolCall]


@dataclass
class World:
    """The probe's own picture of the world. Tool receipts do not write this."""

    effects: list[dict[str, Any]] = field(default_factory=list)

    def changed(self) -> bool:
        return bool(self.effects)


@dataclass
class ScenarioResult:
    scenario_id: str
    battery: str
    title: str
    passed: bool
    fail_severity: str
    summary: str
    remediation: str
    reproduction: list[str]
    mappings: list[Mapping]
    evidence: dict[str, Any]
    rank: int = 50

    @property
    def severity(self) -> str | None:
        return None if self.passed else self.fail_severity
