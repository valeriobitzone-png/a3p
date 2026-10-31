"""Static leaderboard of phantom-success rates from signed badges.

Phantom-success rate is the share of phantom scenarios that failed. Lower is
better. A row is an assessment under A3P Method v1.0. It is not a
statement that a model or agent is safe.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from a3p.method import METHOD_VERSION, verify_badge


def load_badge(path: Path) -> dict[str, Any] | None:
    candidate = path / "badge.json" if path.is_dir() else path
    if not candidate.is_file():
        return None
    loaded = json.loads(candidate.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        return None
    return loaded


def phantom_success_rate(badge: dict[str, Any]) -> float | None:
    total = int(badge.get("phantom_total") or 0)
    if total <= 0:
        return None
    return int(badge.get("phantom_failed") or 0) / total


def collect(paths: list[Path]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    for path in paths:
        badge = load_badge(path)
        label = str(path)
        if badge is None:
            rejected.append({"path": label, "reason": "badge.json missing"})
            continue
        ok, reason = verify_badge(badge)
        if not ok:
            rejected.append({"path": label, "reason": reason})
            continue
        rate = phantom_success_rate(badge)
        rows.append(
            {
                "agent_name": badge.get("agent_name"),
                "agent_version": badge.get("agent_version"),
                "level": badge.get("level"),
                "statement": badge.get("statement"),
                "overall": badge.get("overall"),
                "band": badge.get("band"),
                "phantom_score": badge.get("phantom_score"),
                "phantom_success_rate": None if rate is None else round(rate, 4),
                "phantom_failed": badge.get("phantom_failed"),
                "phantom_total": badge.get("phantom_total"),
                "run_id": badge.get("run_id"),
            }
        )
    rows.sort(key=lambda row: (row["phantom_success_rate"] is None, row["phantom_success_rate"] or 0))
    return {"method_version": METHOD_VERSION, "rows": rows, "rejected": rejected}


def render_site(board: dict[str, Any]) -> str:
    body = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8"/>',
        "<title>A3P phantom-success leaderboard</title>",
        "<style>",
        "body{margin:0;background:#f3efe6;color:#1c1915;font:16px/1.5 Georgia,serif}",
        "main{max-width:920px;margin:0 auto;padding:32px 20px 64px}",
        "table{width:100%;border-collapse:collapse;background:#fffdf8}",
        "th,td{text-align:left;border-bottom:1px solid #d9d1c3;padding:8px}",
        "p.note{border-left:3px solid #1c1915;padding-left:12px}",
        "</style></head><body><main>",
        "<h1>Phantom-success rates</h1>",
        "<p class=\"note\">Rows come from badges that verified under "
        f"A3P Method v{html.escape(str(board.get('method_version') or METHOD_VERSION))}. "
        "Phantom-success rate is failed phantom scenarios divided by phantom scenarios. "
        "Lower is better. A higher phantom battery score is the same fact from the other side. "
        "This page is not a safety guarantee, and a row is not a certification.</p>",
        "<table><thead><tr>",
        "<th>Agent</th><th>Level</th><th>Phantom-success rate</th><th>Phantom score</th><th>Overall</th><th>Band</th>",
        "</tr></thead><tbody>",
    ]
    rows = board.get("rows") or []
    if not rows:
        body.append('<tr><td colspan="6">No verified badge in this set.</td></tr>')
    for row in rows:
        rate = row.get("phantom_success_rate")
        shown = "n/a" if rate is None else f"{rate:.4f}"
        body.append(
            "<tr>"
            f"<td>{html.escape(str(row.get('agent_name') or ''))}</td>"
            f"<td>{html.escape(str(row.get('level') or ''))}</td>"
            f"<td>{shown}</td>"
            f"<td>{html.escape(str(row.get('phantom_score')))}</td>"
            f"<td>{html.escape(str(row.get('overall')))}</td>"
            f"<td>{html.escape(str(row.get('band') or ''))}</td>"
            "</tr>"
        )
    body.append("</tbody></table>")
    body.append("<h2>Rejected</h2><ul>")
    rejected = board.get("rejected") or []
    if not rejected:
        body.append("<li>None.</li>")
    for item in rejected:
        body.append(
            f"<li>{html.escape(str(item.get('path') or ''))}: {html.escape(str(item.get('reason') or ''))}</li>"
        )
    body.append("</ul></main></body></html>\n")
    return "\n".join(body)


def write_site(paths: list[Path], output: Path) -> dict[str, Any]:
    board = collect(paths)
    output.mkdir(parents=True, exist_ok=True)
    (output / "index.html").write_text(render_site(board), encoding="utf-8")
    (output / "board.json").write_text(
        json.dumps(board, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return board
