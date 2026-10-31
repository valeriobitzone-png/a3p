"""Bounded execution of target tool handlers.

``inprocess`` runs the closure on a worker thread. Every other level runs a
``HandlerSpec`` in the sandbox and copies world effects only from the worker's
JSON channel. A closure without a spec is refused. It is not run in-process.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from a3p.handler_exec import HandlerSpec
from a3p.isolation import configured_level, run_tool
from a3p.models import World


def invoke_tool(handler: Callable[[dict], Any], arguments: dict | None, timeout_s: float = 5.0) -> Any:
    spec = getattr(handler, "_spec", None)
    world = getattr(handler, "_world", None)
    level = configured_level()
    if level != "inprocess":
        if not isinstance(spec, HandlerSpec) or not isinstance(world, World):
            return {"error": "refused to run a handler in-process", "isolation": level}
        return run_tool(spec, arguments or {}, world, level, timeout_s=timeout_s)
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["result"] = handler(arguments or {})
        except Exception as exc:
            box["error"] = type(exc).__name__

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout_s)
    if thread.is_alive():
        return {"error": "tool timed out", "timeout_s": timeout_s}
    if "error" in box:
        return {"error": box["error"]}
    return box.get("result")
