"""Probe the two intentionally vulnerable demo agents, plus the other adapters.

The LangGraph agent and the n8n webhook are the demo targets from the MVP plan.
The OpenAI-compatible run uses the same vulnerable policy behind mock:// so the
third adapter is exercised offline. A careful LangGraph run is included so the
sample shows the probes can pass.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from a3p.adapters.langgraph_agent import LangGraphAdapter
from a3p.adapters.n8n_webhook import N8nAdapter, N8nWebhookServer
from a3p.adapters.openai_chat import OpenAIChatAdapter
from a3p.env import setting
from a3p.runner import write_run

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / "demos" / "n8n" / "vulnerable-support-agent.json"


def run_demo(output: Path, sample: Path | None = None) -> None:
    note = demo_isolation_note()
    if note:
        print(note)
    _print_lie()
    output = Path(output)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    _langgraph(output / "langgraph-vulnerable", "vulnerable")
    _langgraph(output / "langgraph-careful", "careful")
    _openai(output / "openai-vulnerable")
    _n8n(output / "n8n-vulnerable")
    for child in sorted(output.iterdir()):
        summary = child / "results.json"
        if summary.is_file():
            report = json.loads(summary.read_text(encoding="utf-8"))
            print(f"{child.name}: score {report['overall']} band {report['band']}")
    print(f"demo written to {output}")
    if sample is not None:
        publish_sample(output, sample)


def publish_sample(output: Path, sample: Path) -> None:
    """Copy the vulnerable LangGraph run. Callers choose the directory."""
    source = Path(output) / "langgraph-vulnerable"
    sample.mkdir(parents=True, exist_ok=True)
    for name in (
        "report.html",
        "report.pdf",
        "ledger.jsonl",
        "auditor.pub",
        "badge.json",
        "badge.svg",
        "repro.json",
    ):
        shutil.copyfile(source / name, sample / name)
    print(f"sample report copied to {sample / 'report.html'}")


def _print_lie() -> None:
    """One visible phantom success, before the full batteries."""
    from a3p.batteries.common import run_scenario
    from a3p.batteries.phantom import phantom_scenarios

    scenario = next(item for item in phantom_scenarios() if item.id == "phantom-tool-structured-ok")
    result = run_scenario(LangGraphAdapter("vulnerable"), scenario)
    evidence = result.evidence
    print("CAUGHT A LIE")
    print("Agent said the email was sent.")
    print(str(evidence.get("final_text") or "")[:500])
    print(f"Observed world: outbox empty (world_changed={evidence.get('world_changed')}).")


def demo_isolation_note() -> str | None:
    """Keep the demo off Docker. An audit run leaves the variable unset."""
    if setting("ISOLATION"):
        return None
    os.environ["A3P_ISOLATION"] = "inprocess"
    return (
        "Demo runs in-process. An audit run with A3P_ISOLATION unset uses gVisor when runsc "
        "is installed, then a container when Docker can start the sandbox image, then nsjail, "
        "then bubblewrap. Set A3P_ISOLATION to force one of those jails."
    )


def _meta(agent_name: str, version: str, scope: str) -> dict:
    return {
        "client": "Northwind Demo (fictional)",
        "agent_name": agent_name,
        "agent_version": version,
        "scope": scope,
        "auditor": "A3P demo",
    }


def _langgraph(directory: Path, policy: str) -> None:
    write_run(
        LangGraphAdapter(policy),
        directory,
        _meta(
            f"LangGraph support agent ({policy})",
            "demo-0.1.0",
            "Fictional staging agent. Email, CRM, refunds, and admin tools are probe-owned. No live side effects.",
        ),
    )


def _openai(directory: Path) -> None:
    write_run(
        OpenAIChatAdapter(base_url="mock://vulnerable", model="a3p-mock", api_key="mock"),
        directory,
        _meta(
            "OpenAI-compatible chat agent (mock model)",
            "demo-0.1.0",
            "Same vulnerable policy behind the chat-completions tool loop. No network call.",
        ),
    )


def _n8n(directory: Path) -> None:
    server = N8nWebhookServer(WORKFLOW, "vulnerable")
    server.start()
    try:
        write_run(
            N8nAdapter(WORKFLOW, "vulnerable", mode="http", server=server),
            directory,
            _meta(
                "n8n-style webhook support agent",
                "demo-0.1.0",
                f"Workflow {WORKFLOW.name} served at {server.url}. Mock runner, not the n8n product.",
            ),
        )
    finally:
        server.stop()
