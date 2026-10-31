"""Declarative tool handlers.

Battery tools are a spec, not a closure the sandbox would have to pickle.
The worker runs ``apply_spec`` and returns the new effect list on stdout.
The parent applies that list only after ``accept_effects`` checks it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HandlerSpec:
    kind: str
    payload: Any = None
    effect: bool = False
    effect_name: str = "action"
    lie: bool = False
    echo: str = "arguments"


def spec_to_json(spec: HandlerSpec) -> dict[str, Any]:
    return {
        "kind": spec.kind,
        "payload": spec.payload,
        "effect": spec.effect,
        "effect_name": spec.effect_name,
        "lie": spec.lie,
        "echo": spec.echo,
    }


def spec_from_json(raw: dict[str, Any]) -> HandlerSpec:
    return HandlerSpec(
        kind=str(raw.get("kind") or ""),
        payload=raw.get("payload"),
        effect=bool(raw.get("effect")),
        effect_name=str(raw.get("effect_name") or "action"),
        lie=bool(raw.get("lie")),
        echo=str(raw.get("echo") or "arguments"),
    )


def apply_spec(spec: HandlerSpec, args: dict[str, Any], effects: list[Any]) -> tuple[Any, list[Any]]:
    """Return (tool result, full effect list). Does not touch the parent world."""
    current = json.loads(json.dumps(effects))
    if not isinstance(current, list):
        current = []
    if spec.kind == "static":
        return _copy(spec.payload), current
    if spec.kind == "echo":
        if spec.echo == "accepted":
            result: Any = {"ok": True, "accepted": args}
        elif spec.echo == "ok":
            result = {"ok": True}
        else:
            result = {"ok": True, "arguments": args}
        return result, current
    if spec.kind == "phantom":
        if spec.effect:
            current.append({"tool": spec.effect_name, "arguments": args})
        return _copy(spec.payload), current
    if spec.kind == "oracle":
        found = True if spec.lie else bool(current)
        return {
            "found": found,
            "verified": found,
            "count": 0 if spec.lie else len(current),
        }, current
    raise ValueError(f"unknown handler spec {spec.kind!r}")


def accept_effects(spec: HandlerSpec, before: list[Any], reported: Any) -> list[Any]:
    """Keep history. Allow at most one new effect, and only when the spec says so."""
    prior = json.loads(json.dumps(before))
    if not isinstance(prior, list) or not isinstance(reported, list):
        raise ValueError("effects were not a list")
    if reported[: len(prior)] != prior:
        raise ValueError("worker rewrote effect history")
    added = reported[len(prior) :]
    if len(added) > 1 or (added and not spec.effect):
        raise ValueError("worker added an effect the spec does not allow")
    for item in added:
        if not isinstance(item, dict) or "tool" not in item:
            raise ValueError("effect was not an object with a tool name")
    return reported


def _copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy(item) for item in value]
    return value
