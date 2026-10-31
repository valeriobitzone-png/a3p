"""Full-battery live matrix. One local model at a time, two seeds.

Hosted providers run only when the matching API key is set. Results are
rewritten after every seed so a stopped run still leaves numbers behind.

Ollama is started with a 4096-token context. The model cards advertise
8k–128k, and those KV caches do not fit this machine.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from a3p.adapters.openai_chat import OpenAIChatAdapter
from a3p.batteries import BATTERIES
from a3p.isolation import attest, best_level
from a3p.live import run_seed, summarize

SEEDS = [1, 2]
PREFERRED = [
    "qwen2.5:1.5b",
    "qwen2.5:3b",
    "phi3:mini",
    "llama3.2:3b",
    "gemma2:2b",
    "qwen2.5:7b",
    "llama3.1:8b",
    "mistral:7b",
    "gemma2:9b",
]
HOSTED = [
    ("openai", "OPENAI_API_KEY", "https://api.openai.com/v1", "gpt-4o-mini"),
    ("groq", "GROQ_API_KEY", "https://api.groq.com/openai/v1", "llama-3.1-8b-instant"),
    ("openrouter", "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1", "openai/gpt-4o-mini"),
    ("gemini", "GEMINI_API_KEY", "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.0-flash"),
    ("anthropic", "ANTHROPIC_API_KEY", "", "claude-3-5-haiku-latest"),
]


def installed_models() -> list[str]:
    with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as response:
        body = json.loads(response.read().decode("utf-8"))
    names = {item["name"] for item in body.get("models", [])}
    ordered = [name for name in PREFERRED if name in names]
    ordered.extend(sorted(names - set(ordered)))
    return ordered


def all_scenarios():
    rows = []
    for factory in BATTERIES.values():
        rows.extend(factory())
    return rows


def factory_for(base_url: str, model: str, api_key: str):
    def build(seed: int) -> OpenAIChatAdapter:
        return OpenAIChatAdapter(
            base_url=base_url,
            model=model,
            api_key=api_key,
            timeout=90.0,
            retries=0,
            seed=seed,
            max_tokens=256,
        )

    return build


def _large(model: str) -> bool:
    return any(tag in model for tag in ("7b", "8b", "9b", "14b"))


def stop_n8n() -> None:
    subprocess.run(["sudo", "-n", "docker", "stop", "a3n8n"], check=False, capture_output=True)


def unload(model: str) -> None:
    try:
        urllib.request.urlopen(
            urllib.request.Request(
                "http://127.0.0.1:11434/api/generate",
                data=json.dumps({"model": model, "keep_alive": 0}).encode(),
                headers={"Content-Type": "application/json"},
            ),
            timeout=30,
        ).read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"  unload failed: {exc}", flush=True)


def warmup(model: str) -> str | None:
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with the single word ok."}],
        "stream": False,
        "options": {"temperature": 0, "num_predict": 8, "num_ctx": 4096},
    }
    request = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def pack(name: str, reports, scenarios) -> dict:
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
    return {
        "summary": summarize(reports),
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
        "name": name,
    }


def main() -> int:
    os.environ["A3P_ISOLATION"] = "auto"
    scenarios = all_scenarios()
    document: dict = {
        "round": 3,
        "battery": "full",
        "scenario_count": len(scenarios),
        "seeds": SEEDS,
        "isolation": attest(best_level()),
        "models": {},
        "hosted": {},
        "notes": {
            "claim_rate": "Share of scenarios with a success claim, a forbidden tool call, or a canary leak.",
            "scoring": "Deterministic given the same scenario results. Variance is the model.",
            "agent_process": "The model server stays outside the sandbox. Tool probes run inside it.",
            "context": "Ollama context was capped at 4096 tokens. Model cards advertise 8192 to 131072.",
            "max_tokens": 256,
        },
    }
    out = Path("docs/live-results.json")

    def flush() -> None:
        out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    hosted_ready: list[tuple[str, str, str, str]] = []
    for name, env_key, base_url, model in HOSTED:
        key = os.environ.get(env_key, "")
        if name == "gemini" and not key:
            key = os.environ.get("GOOGLE_API_KEY", "")
        if name == "anthropic":
            base_url = os.environ.get("A3P_ANTHROPIC_BASE_URL", "")
        if not key or not base_url:
            document["hosted"][name] = {
                "status": "not_run",
                "reason": (
                    f"{env_key} is unset"
                    if not key
                    else "native API is not chat-completions; set A3P_ANTHROPIC_BASE_URL"
                ),
                "config": f"demos/configs/hosted/{name}.yaml",
            }
            continue
        hosted_ready.append((name, base_url, model, key))
    flush()

    for model in installed_models():
        print(f"== ollama {model}", flush=True)
        if _large(model):
            stop_n8n()
        failure = warmup(model)
        if failure:
            print(f"  load failed: {failure}", flush=True)
            document["models"][model] = {"status": "not_run", "reason": failure}
            flush()
            unload(model)
            continue
        reports = []
        builder = factory_for("http://127.0.0.1:11434/v1", model, "ollama")
        try:
            for seed in SEEDS:
                print(f"  seed {seed}", flush=True)
                started = time.time()

                def progress(scenario, result, started=started) -> None:
                    print(
                        f"    {scenario.id} pass={result.passed} {time.time() - started:.0f}s",
                        flush=True,
                    )

                report = run_seed(builder, seed, scenarios, on_result=progress)
                reports.append(report)
                print(
                    f"    overall={report.overall} tools={report.tool_call_rate:.2f} "
                    f"signals={report.claim_rate:.2f} errors={report.errors} scores={report.scores}",
                    flush=True,
                )
                document["models"][model] = pack(model, reports, scenarios)
                flush()
                if report.errors == len(scenarios):
                    document["models"][model]["note"] = "Every scenario errored. The other seed was skipped."
                    flush()
                    break
        except Exception as exc:
            document["models"][model] = {
                "status": "error",
                "reason": f"{type(exc).__name__}: {exc}",
                "partial_seeds": len(reports),
            }
            flush()
            print(f"  model failed: {exc}", flush=True)
        unload(model)

    for name, base_url, model, key in hosted_ready:
        print(f"== hosted {name}", flush=True)
        reports = []
        builder = factory_for(base_url, model, key)
        for seed in SEEDS:
            report = run_seed(builder, seed, scenarios)
            reports.append(report)
        document["hosted"][name] = pack(name, reports, scenarios)
        flush()
    flush()
    print(f"wrote {out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
