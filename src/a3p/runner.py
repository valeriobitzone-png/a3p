"""Run batteries, seal a ledger, write HTML and PDF."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from a3ep import __version__ as a3ep_version
from a3p import __version__
from a3p.batteries import BATTERIES
from a3p.batteries.common import Scenario, run_scenario
from a3p.batteries.external import load_garak, load_promptfoo
from a3p.canaries import redact_obj
from a3p.claims import push_judge, reset_judge
from a3p.isolation import isolation_summary
from a3p.keys import load_private
from a3p.ledger import LedgerWriter
from a3p.method import (
    METHOD_VERSION,
    badge_body,
    components_for,
    criteria_from_report,
    level_for,
    model_component,
    render_badge_svg,
    repro_bundle,
    seal_badge,
    statement,
)
from a3p.models import ScenarioResult
from a3p.ollama_isolation import attested as ollama_attested
from a3p.report_html import render_html
from a3p.report_pdf import render_pdf
from a3p.scoring import (
    BATTERY_ORDER,
    band,
    battery_score,
    decision,
    overall_score,
    top_risks,
)


def execute(
    adapter: Any,
    battery_names: list[str] | None = None,
    on_scenario: Any | None = None,
) -> list[ScenarioResult]:
    names = battery_names or list(BATTERY_ORDER)
    results: list[ScenarioResult] = []
    for name in names:
        scenarios: list[Scenario] = BATTERIES[name]()
        for scenario in scenarios:
            result = run_scenario(adapter, scenario)
            results.append(result)
            if on_scenario is not None:
                on_scenario(result)
    return results


def write_run(
    adapter: Any,
    directory: Path,
    meta: dict[str, Any],
    *,
    battery_names: list[str] | None = None,
    promptfoo: str | None = None,
    garak: str | None = None,
    results: list[ScenarioResult] | None = None,
    judge: object | None = None,
    on_scenario: Any | None = None,
) -> dict:
    token = push_judge(judge)
    try:
        return _write(adapter, directory, meta, battery_names, promptfoo, garak, results, on_scenario)
    finally:
        reset_judge(token)


def _write(
    adapter: Any,
    directory: Path,
    meta: dict[str, Any],
    battery_names: list[str] | None,
    promptfoo: str | None,
    garak: str | None,
    results: list[ScenarioResult] | None,
    on_scenario: Any | None = None,
) -> dict:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    seed_count = _seed_count(meta.get("seeds"))
    if results is None:
        results = []
        for seed in range(seed_count):
            for result in execute(adapter, battery_names, on_scenario):
                result.evidence["seed"] = seed
                results.append(result)
    if promptfoo:
        results.extend(load_promptfoo(promptfoo))
    if garak:
        results.extend(load_garak(garak))

    created = datetime.now(UTC).replace(microsecond=0).isoformat()
    run_id = uuid.uuid4().hex[:12]
    ledger = LedgerWriter(directory)
    ledger.append(
        "run_start",
        {
            "run_id": run_id,
            "created_at": created,
            "a3p": __version__,
            "a3ep": a3ep_version,
            "spec": "A3-EP 0.2.0",
            "adapter": getattr(adapter, "name", meta.get("adapter", "unknown")),
            "agent_name": meta.get("agent_name"),
            "agent_version": meta.get("agent_version"),
            "client": meta.get("client"),
            "scope": meta.get("scope"),
            "batteries": battery_names or list(BATTERY_ORDER),
        },
    )
    for result in results:
        ledger.append("scenario", redact_obj(_result_payload(run_id, result)))

    by_name = _grouped(results)
    scores = {name: battery_score(by_name.get(name, [])) for name in by_name}
    overall = overall_score(scores)
    run_band = band(overall, results)
    ledger.append(
        "run_end",
        {"run_id": run_id, "scores": scores, "overall": overall, "band": run_band},
    )
    sealed = ledger.seal()
    isolation = isolation_summary()
    tool_level = str(isolation.get("level") or "inprocess")
    base_url = str(getattr(adapter, "base_url", "") or "")
    proxy = getattr(adapter, "proxy", None)
    components = components_for(
        tool_level,
        isolation,
        _model_component(adapter, base_url, str(proxy) if proxy else None),
    )
    report = redact_obj(
        _report(
        results,
        {
            **meta,
            "run_id": run_id,
            "created_at": created,
            "adapter": getattr(adapter, "name", meta.get("adapter", "")),
            "methodology": (
                f"A3P Method v{METHOD_VERSION} / A3P {__version__} / "
                f"A3-EP {a3ep_version} spec 0.2.0"
            ),
            "a3p_version": __version__,
            "a3ep_version": a3ep_version,
            "method_version": METHOD_VERSION,
            "seeds": seed_count,
            "ledger_head": sealed.head,
            "public_key_hex": sealed.public_key_hex,
            "isolation_level": tool_level,
            "isolation": isolation,
            "components": components,
        },
        scores,
        overall,
        run_band,
    ))
    if isinstance(report, dict):
        criteria = criteria_from_report(report)
        level = level_for(criteria)
        meta_out = report.get("meta")
        if isinstance(meta_out, dict):
            meta_out["assurance_level"] = level
            meta_out["assessment"] = statement(level)
        _write_authority(directory, report, criteria, level)
    (directory / "report.html").write_text(render_html(report), encoding="utf-8")
    pdf_path = directory / "report.pdf"
    render_pdf(report, pdf_path)
    from a3p.report_pdf import sign_pdf

    sign_pdf(pdf_path, ledger.signing_key)
    from a3p.attest import sign_result, statement_for

    assessment = ""
    meta_now = report.get("meta") if isinstance(report, dict) else None
    if isinstance(meta_now, dict):
        assessment = str(meta_now.get("assessment") or "")
    document = statement_for(
        "results.json",
        json.dumps(report, sort_keys=True, default=str).encode("utf-8"),
        {"statement": assessment},
    )
    (directory / "attestation.json").write_text(
        json.dumps(sign_result(document, ledger.signing_key), indent=2) + "\n",
        encoding="utf-8",
    )
    (directory / "results.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    report["output_dir"] = str(directory)
    return cast(dict[str, Any], report)


def _model_component(adapter: Any, base_url: str, proxy: str | None) -> dict[str, Any]:
    host = urlsplit(base_url).hostname or "" if base_url else ""
    isolated = False
    from a3p.env import setting

    if host in {"127.0.0.1", "localhost"} and (setting("OLLAMA_ISOLATION") or "").strip() == "container":
        isolated = ollama_attested()
    tls = bool(getattr(adapter, "tls_intercept", False))
    return model_component(base_url, proxy=proxy, ollama_isolated=isolated, tls_intercept=tls)


def _write_authority(directory: Path, report: dict[str, Any], criteria: dict[str, Any], level: str) -> None:
    private, _path = load_private()
    body = badge_body(report, criteria, level)
    signed = seal_badge(body, private, _keyless_bundle(body))
    (directory / "badge.json").write_text(
        json.dumps(signed, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (directory / "badge.svg").write_text(render_badge_svg(signed), encoding="utf-8")
    (directory / "repro.json").write_text(
        json.dumps(repro_bundle(report), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _keyless_bundle(body: dict[str, Any]) -> dict[str, Any] | None:
    """Fulcio bundle over the badge body, or None when no ambient OIDC token exists."""
    from a3p.attest import AttestationError, KeylessUnavailable, sign_keyless
    from a3p.method import keyless_payload

    try:
        signed = sign_keyless(keyless_payload(body))
    except (KeylessUnavailable, AttestationError):
        return None
    return signed if isinstance(signed, dict) else None


def _seed_count(value: object) -> int:
    if value is None or value == "":
        return 1
    try:
        count = int(str(value))
    except (TypeError, ValueError):
        return 1
    return min(max(count, 1), 8)


def _grouped(results: list[ScenarioResult]) -> dict[str, list[ScenarioResult]]:
    grouped: dict[str, list[ScenarioResult]] = {}
    for result in results:
        grouped.setdefault(result.battery, []).append(result)
    return grouped


def _result_payload(run_id: str, result: ScenarioResult) -> dict:
    payload = asdict(result)
    payload["run_id"] = run_id
    payload["passed"] = result.passed
    return payload


def _report(
    results: list[ScenarioResult],
    meta: dict[str, Any],
    scores: dict[str, int],
    overall: int,
    run_band: str,
) -> dict[str, Any]:
    grouped = _grouped(results)
    batteries = []
    for name in list(BATTERY_ORDER) + [name for name in grouped if name not in BATTERY_ORDER]:
        rows = grouped.get(name, [])
        if name not in grouped:
            continue
        batteries.append(
            {
                "name": name,
                "score": scores[name],
                "passed": sum(1 for row in rows if row.passed),
                "failed": sum(1 for row in rows if not row.passed),
            }
        )
    dumped = [asdict(result) for result in results]
    return {
        "meta": meta,
        "overall": overall,
        "band": run_band,
        "decision": decision(overall, results),
        "batteries": batteries,
        "top_risks": [asdict(result) for result in top_risks(results)],
        "results": dumped,
    }
