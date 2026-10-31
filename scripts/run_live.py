"""Run the live subset against Ollama, LangGraph, and the n8n AI agent."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

from a3p.live import langgraph_factory, live_scenarios, openai_factory, run_seed, summarize
from a3p.models import AgentResult


class N8nAiAgent:
    """Real n8n AI Agent node. This workflow has no probe tools, only the model."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.name = "n8n-ai-agent"

    def run(self, *, task: str, system: str, tools: list, max_turns: int = 6, followups: list[str] | None = None) -> AgentResult:
        del tools, max_turns
        parts: list[str] = []
        for segment in [task, *(followups or [])]:
            response = httpx.post(self.url, json={"task": segment, "system": system}, timeout=90.0)
            response.raise_for_status()
            body = response.json()
            parts.append(str(body.get("text") or body.get("output") or ""))
        return AgentResult("\n".join(parts), [])


def main() -> int:
    base = "http://127.0.0.1:11434/v1"
    model = "qwen2.5:1.5b"
    n8n_url = "http://127.0.0.1:5678/webhook/a3p"
    scenarios = live_scenarios()
    seeds = [1, 2, 3]
    targets = {
        "openai-compatible": openai_factory(base, model),
        "langgraph": langgraph_factory(base, model),
        "n8n": lambda seed: N8nAiAgent(n8n_url),
    }
    document: dict = {"model": model, "seeds": seeds, "scenarios": [item.id for item in scenarios], "targets": {}}
    for name, factory in targets.items():
        print(f"== {name}", flush=True)
        reports = []
        for seed in seeds:
            print(f"  seed {seed}", flush=True)
            report = run_seed(factory, seed, scenarios)
            reports.append(report)
            print(
                f"    overall={report.overall} tools={report.tool_call_rate:.2f} "
                f"signals={report.claim_rate:.2f} errors={report.errors}",
                flush=True,
            )
        stats = summarize(reports)
        per_scenario = []
        for index, scenario in enumerate(scenarios):
            outcomes = [reports[run].results[index].passed for run in range(len(reports))]
            per_scenario.append(
                {
                    "id": scenario.id,
                    "battery": scenario.battery,
                    "passed": outcomes,
                    "stable": len(set(outcomes)) == 1,
                }
            )
        document["targets"][name] = {
            "summary": stats,
            "seeds": [
                {
                    "seed": report.seed,
                    "overall": report.overall,
                    "scores": report.scores,
                    "tool_call_rate": report.tool_call_rate,
                    "claim_rate": report.claim_rate,
                    "errors": report.errors,
                }
                for report in reports
            ],
            "scenarios": per_scenario,
        }
    out = Path("docs/live-results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
