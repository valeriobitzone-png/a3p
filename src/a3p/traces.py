"""Read an OpenTelemetry or Langfuse export and compare claims to world reads."""

from __future__ import annotations

from typing import Any

from a3p.claims import claims_done
from a3p.world.base import Observation


def _span(name: str, text: str, kind: str) -> dict[str, str]:
    return {"name": name, "text": text, "kind": kind}


def otlp_spans(document: dict[str, Any]) -> list[dict[str, str]]:
    spans: list[dict[str, str]] = []
    resources = document.get("resourceSpans") or document.get("resource_spans") or []
    if not isinstance(resources, list):
        return []
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        scopes = resource.get("scopeSpans") or resource.get("scope_spans") or []
        if not isinstance(scopes, list):
            continue
        for scope in scopes:
            if not isinstance(scope, dict):
                continue
            for span in scope.get("spans") or []:
                if not isinstance(span, dict):
                    continue
                attrs = span.get("attributes") or []
                text = ""
                if isinstance(attrs, list):
                    for attr in attrs:
                        if isinstance(attr, dict) and str(attr.get("key")) in {"gen_ai.completion", "output"}:
                            value = attr.get("value")
                            if isinstance(value, dict):
                                text = str(value.get("stringValue") or value.get("string_value") or "")
                name = str(span.get("name") or "")
                kind = "tool" if "tool" in name.lower() else "assistant"
                if text or name:
                    spans.append(_span(name, text, kind))
    return spans


def langfuse_spans(document: dict[str, Any]) -> list[dict[str, str]]:
    observations = document.get("observations") or document.get("traces") or []
    if isinstance(document.get("trace"), dict):
        observations = [document["trace"], *list(observations if isinstance(observations, list) else [])]
    spans: list[dict[str, str]] = []
    if not isinstance(observations, list):
        return []
    for item in observations:
        if not isinstance(item, dict):
            continue
        text = str(item.get("output") or item.get("completion") or "")
        name = str(item.get("name") or item.get("id") or "")
        kind = "tool" if str(item.get("type") or "").lower() in {"tool", "span", "generation"} and "tool" in name.lower() else "assistant"
        if str(item.get("type") or "").lower() == "tool":
            kind = "tool"
        spans.append(_span(name, text, kind))
    return spans


def check_trace(spans: list[dict[str, str]], observations: list[Observation]) -> list[dict[str, Any]]:
    """Flag an assistant claim of completion when no world read succeeded."""
    world_ok = any(item.ok for item in observations)
    findings: list[dict[str, Any]] = []
    for span in spans:
        if span.get("kind") == "tool":
            continue
        text = span.get("text") or ""
        if claims_done(text) and not world_ok:
            findings.append(
                {
                    "span": span.get("name"),
                    "claim": text[:240],
                    "ok": False,
                    "summary": "The trace claims a completed action. No world read in this check succeeded.",
                }
            )
    return findings
