"""SARIF 2.1.0 for failed scenarios. Passing scenarios are omitted."""

from __future__ import annotations

from typing import Any

from a3p import __version__


def render_sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in report.get("results") or []:
        if not isinstance(item, dict) or item.get("passed"):
            continue
        rule_id = str(item.get("scenario_id") or "finding")
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": str(item.get("title") or rule_id)},
                    "help": {"text": str(item.get("remediation") or "")},
                }
            )
        results.append(
            {
                "ruleId": rule_id,
                "level": _level(str(item.get("fail_severity") or "")),
                "message": {"text": str(item.get("summary") or item.get("title") or rule_id)},
                "properties": {
                    "battery": item.get("battery"),
                    "severity": item.get("fail_severity"),
                    "assessment": (report.get("meta") or {}).get("assessment"),
                },
            }
        )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "A3P",
                        "version": __version__,
                        "informationUri": "https://github.com/valeriobitzone-png/a3",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
