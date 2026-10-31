"""Repeat a small battery against a real OpenAI-compatible model.

The scoring function does not use randomness. Variance in this report is the
model's variance across seeds. A high score from a model that never calls a
tool is not the same result as a careful agent that calls tools and refuses
to treat receipts as facts.
"""

from __future__ import annotations

import statistics
from collections.abc import Callable
from dataclasses import dataclass

from a3p.adapters.langgraph_model import LangGraphModelAdapter
from a3p.adapters.openai_chat import OpenAIChatAdapter
from a3p.batteries import BATTERIES
from a3p.batteries.common import Scenario, run_scenario
from a3p.models import ScenarioResult
from a3p.scoring import battery_score, overall_score

LIVE_IDS = (
    "phantom-tool-structured-ok",
    "phantom-lying-oracle",
    "phantom-chain-receipts",
    "inj-indirect-email",
    "inj-control-benign-ignore",
    "perm-delete-customer",
    "perm-control-readonly",
    "leak-system-prompt",
    "leak-art50",
    "leak-control-quiet",
)


@dataclass(frozen=True)
class SeedReport:
    seed: int
    overall: int
    scores: dict[str, int]
    tool_call_rate: float
    claim_rate: float
    errors: int
    results: list[ScenarioResult]


def live_scenarios() -> list[Scenario]:
    chosen = []
    for factory in BATTERIES.values():
        for scenario in factory():
            if scenario.id in LIVE_IDS:
                chosen.append(scenario)
    missing = [sid for sid in LIVE_IDS if sid not in {item.id for item in chosen}]
    if missing:
        raise RuntimeError(f"live subset missing scenarios: {missing}")
    return chosen


def run_seed(
    adapter_for_seed: Callable[[int], object],
    seed: int,
    scenarios: list[Scenario],
    on_result: Callable[[Scenario, ScenarioResult], None] | None = None,
) -> SeedReport:
    adapter = adapter_for_seed(seed)
    results: list[ScenarioResult] = []
    for scenario in scenarios:
        result = run_scenario(adapter, scenario)
        results.append(result)
        if on_result is not None:
            on_result(scenario, result)
    grouped: dict[str, list[ScenarioResult]] = {}
    for result in results:
        grouped.setdefault(result.battery, []).append(result)
    scores = {name: battery_score(rows) for name, rows in grouped.items()}
    calls = 0
    claims = 0
    errors = 0
    for result in results:
        evidence = result.evidence or {}
        if evidence.get("error"):
            errors += 1
        if evidence.get("tool_calls"):
            calls += 1
        if evidence.get("claimed_done") or evidence.get("forbidden_calls") or evidence.get("leaked_in_answer"):
            claims += 1
    count = max(len(results), 1)
    return SeedReport(
        seed=seed,
        overall=overall_score(scores),
        scores=scores,
        tool_call_rate=calls / count,
        claim_rate=claims / count,
        errors=errors,
        results=results,
    )


def openai_factory(base_url: str, model: str, api_key: str = "ollama") -> Callable[[int], OpenAIChatAdapter]:
    def build(seed: int) -> OpenAIChatAdapter:
        return OpenAIChatAdapter(
            base_url=base_url,
            model=model,
            api_key=api_key,
            timeout=45.0,
            retries=1,
            seed=seed,
        )

    return build


def langgraph_factory(base_url: str, model: str, api_key: str = "ollama") -> Callable[[int], LangGraphModelAdapter]:
    def build(seed: int) -> LangGraphModelAdapter:
        return LangGraphModelAdapter(base_url, model, api_key, timeout=45.0, seed=seed)

    return build


def summarize(reports: list[SeedReport]) -> dict[str, float | int]:
    scores = [report.overall for report in reports]
    return {
        "runs": len(scores),
        "mean": statistics.fmean(scores) if scores else 0.0,
        "stdev": statistics.pstdev(scores) if len(scores) > 1 else 0.0,
        "min": min(scores) if scores else 0,
        "max": max(scores) if scores else 0,
    }
