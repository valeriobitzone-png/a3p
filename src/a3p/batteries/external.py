"""Import Promptfoo and Garak results. Optional. The built-in suite does not need them.

Promptfoo: a result with `success: false` is an assertion failure, so the
attack (or the eval) was not blocked. We record that as a finding.

Garak: JSONL rows. A row is a finding when `vulnerable` is true, or when
`entry_type` is `attempt` and `status` is 1 (garak's hit on that attempt in
the subset this importer documents). Rows without those fields are skipped.

This is a wrapper around exported JSON, not a reimplementation of either scanner.
If the `promptfoo` or `garak` executable is on PATH, `run_if_available` can
shell out; the demo and the tests never require that.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from a3p.mappings import m
from a3p.models import Mapping, ScenarioResult


def load_promptfoo(path: str | Path) -> list[ScenarioResult]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = _promptfoo_rows(document)
    results = []
    for index, row in enumerate(rows):
        success = row.get("success")
        if success is None and isinstance(row.get("gradingResult"), dict):
            success = row["gradingResult"].get("pass")
        if success is not False:
            continue
        description = (
            (row.get("testCase") or {}).get("description")
            or row.get("description")
            or f"promptfoo result {index}"
        )
        output = ""
        response = row.get("response") or {}
        if isinstance(response, dict):
            output = str(response.get("output") or "")
        elif isinstance(response, str):
            output = response
        prompt = row.get("prompt")
        if isinstance(prompt, dict):
            prompt = prompt.get("raw") or prompt.get("display") or ""
        results.append(
            _finding(
                scenario_id=f"promptfoo-{index}",
                title=str(description),
                summary=f"Promptfoo reported a failed assertion: {description}",
                evidence={"prompt": str(prompt)[:2000], "output": output[:2000], "source": "promptfoo"},
                mappings=m(("owasp-llm", "LLM01"), ("owasp-agentic", "ASI01"), ("mitre-atlas", "AML.T0051")),
            )
        )
    return results


def load_garak(path: str | Path) -> list[ScenarioResult]:
    results = []
    index = 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        hit = row.get("vulnerable") is True or (
            row.get("entry_type") == "attempt" and row.get("status") == 1
        )
        if not hit:
            continue
        probe = row.get("probe") or row.get("probe_classname") or "garak"
        output = row.get("output") or row.get("outputs") or ""
        results.append(
            _finding(
                scenario_id=f"garak-{index}",
                title=f"Garak hit: {probe}",
                summary=f"Garak recorded a hit for {probe}.",
                evidence={
                    "probe": str(probe),
                    "prompt": str(row.get("prompt") or "")[:2000],
                    "output": str(output)[:2000],
                    "source": "garak",
                },
                mappings=m(("owasp-llm", "LLM01"), ("mitre-atlas", "AML.T0051")),
            )
        )
        index += 1
    return results


def run_if_available(tool: str, args: list[str], timeout_s: float = 60.0) -> str | None:
    """Run promptfoo or garak if it is installed. Returns stdout, or None if missing."""
    if tool not in {"promptfoo", "garak"}:
        raise ValueError("tool must be promptfoo or garak")
    binary = shutil.which(tool)
    if not binary:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 — tool name is allowlisted, args come from the operator
            [binary, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{tool} timed out after {timeout_s}s") from exc
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"{tool} exited {completed.returncode}")
    return completed.stdout


def _promptfoo_rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    results = document.get("results")
    rows: list[Any] = []
    if isinstance(results, dict) and isinstance(results.get("results"), list):
        rows = results["results"]
    elif isinstance(results, list):
        rows = results
    elif isinstance(document.get("evals"), list):
        rows = document["evals"]
    return [row for row in rows if isinstance(row, dict)]


def _finding(
    *,
    scenario_id: str,
    title: str,
    summary: str,
    evidence: dict,
    mappings: list[Mapping],
) -> ScenarioResult:
    return ScenarioResult(
        scenario_id=scenario_id,
        battery="injection",
        title=title,
        passed=False,
        fail_severity="high",
        summary=summary,
        remediation=(
            "Review the imported case in the originating tool, then apply the same "
            "fix as the built-in injection battery: untrusted text is data, not instructions."
        ),
        reproduction=[
            "Re-run the exported Promptfoo or Garak file.",
            "Import it again with a3p run --promptfoo or --garak.",
        ],
        mappings=mappings,
        evidence=evidence,
        rank=25,
    )
