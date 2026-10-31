"""Scenario builder shared by the batteries."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from a3p.handler_exec import HandlerSpec, apply_spec
from a3p.models import (
    AgentResult,
    BoundTool,
    Mapping,
    PublicTool,
    ScenarioResult,
    World,
)


@dataclass
class Scenario:
    id: str
    battery: str
    title: str
    task: str
    system: str
    fail_severity: str
    summary: str
    remediation: str
    reproduction: list[str]
    mappings: list[Mapping]
    build_tools: Callable[[], tuple[World, list[BoundTool]]]
    evaluate: Callable[[AgentResult, World], tuple[bool, dict]]
    rank: int = 50
    followups: list[str] = field(default_factory=list)


def tool(
    name: str,
    description: str,
    handler: Callable[[dict], Any] | None = None,
    *,
    properties: dict | None = None,
    annotations: dict | None = None,
    spec: HandlerSpec | None = None,
    world: World | None = None,
) -> BoundTool:
    """Bind a tool. A spec is what the sandbox runs; the closure is the in-process path."""
    if spec is None and handler is not None:
        found = getattr(handler, "_spec", None)
        if isinstance(found, HandlerSpec):
            spec = found
    if spec is not None:
        handler = _from_spec(spec, world)
    if handler is None:
        raise ValueError(f"tool {name} has neither a handler nor a spec")
    return BoundTool(
        public=PublicTool(
            name=name,
            description=description,
            parameters={"type": "object", "properties": properties or {}, "additionalProperties": False},
            annotations=annotations or {},
        ),
        handler=handler,
    )


def _from_spec(spec: HandlerSpec, world: World | None) -> Callable[[dict], Any]:
    def handler(args: dict) -> Any:
        result, effects = apply_spec(spec, args or {}, list(world.effects) if world is not None else [])
        if world is not None:
            world.effects[:] = effects
        return result

    handler._spec = spec  # type: ignore[attr-defined]
    handler._world = world  # type: ignore[attr-defined]
    return handler


def run_scenario(adapter: Any, scenario: Scenario) -> ScenarioResult:
    world, tools = scenario.build_tools()
    error = None
    try:
        result = adapter.run(
            task=scenario.task,
            system=scenario.system,
            tools=tools,
            max_turns=6,
            followups=scenario.followups,
        )
    except Exception as exc:  # a down target is a failed probe, not a crash of the suite
        result = AgentResult(final_text="", tool_calls=[])
        error = f"{type(exc).__name__}: {exc}"
    passed, details = scenario.evaluate(result, world)
    if error:
        passed = False
        details = {**details, "error": error}
    evidence = {
        "final_text": result.final_text,
        "tool_calls": [
            {"name": call.name, "arguments": call.arguments, "result": call.result}
            for call in result.tool_calls
        ],
        **details,
    }
    return ScenarioResult(
        scenario_id=scenario.id,
        battery=scenario.battery,
        title=scenario.title,
        passed=passed,
        fail_severity=scenario.fail_severity,
        summary=scenario.summary,
        remediation=scenario.remediation,
        reproduction=list(scenario.reproduction),
        mappings=list(scenario.mappings),
        evidence=_jsonable(evidence),
        rank=scenario.rank,
    )


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return str(value)


def called(result: AgentResult) -> list[str]:
    return [call.name for call in result.tool_calls]


def args_blob(result: AgentResult) -> str:
    parts = []
    for call in result.tool_calls:
        parts.append(str(call.arguments))
    return "\n".join(parts)
