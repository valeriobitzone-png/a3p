"""Local run history. Compares failed scenario ids between two sealed runs.

The server binds loopback unless the caller passes a token and asks for
another host. The token is compared as a hash so a short header cannot throw.
Pages: history, one run, the latest regression, and a G3 sample badge.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import html
import ipaddress
import json
import math
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
BATTERIES = ("phantom", "injection", "permission", "leakage")
BATTERY_LABELS = {
    "phantom": "Phantom (false ok)",
    "injection": "Injection",
    "permission": "Permission",
    "leakage": "Leakage",
}
LEVELS = ("A3P-L0", "A3P-L1", "A3P-L2", "A3P-L3")
# L0 is not in the G3 palette. Ink is the documented stand-in. No green.
LEVEL_INK = {
    "A3P-L0": "#12141a",
    "A3P-L1": "#5f6f7f",
    "A3P-L2": "#1c4e6e",
    "A3P-L3": "#5a3d6b",
}
_FONT_FILES = (
    ("Inter", "400", "inter-latin-400.woff2"),
    ("Inter", "500", "inter-latin-500.woff2"),
    ("Inter", "600", "inter-latin-600.woff2"),
    ("Inter", "700", "inter-latin-700.woff2"),
    ("Source Serif Pro", "400", "source-serif-pro-400.woff2"),
    ("Source Serif Pro", "600", "source-serif-pro-600.woff2"),
)
_LOGO = (
    '<svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 36" '
    'width="32" height="36" role="img" aria-label="A3P">'
    '<rect x="1.5" y="3.5" width="29" height="29" rx="8" fill="none" '
    'stroke="#12141a" stroke-width="1.85"/>'
    '<path d="M8.6 18.2 13.2 23 23.4 11.6" fill="none" stroke="#1c4e6e" '
    'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
    "</svg>"
)


def _score(value: object) -> int:
    if isinstance(value, bool) or isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    return loaded


def load_history(root: str | Path) -> list[dict[str, Any]]:
    base = Path(root)
    rows: list[dict[str, Any]] = []
    if not base.is_dir():
        return rows
    if (base / "results.json").is_file():
        candidates = [base]
    else:
        candidates = [item for item in base.iterdir() if item.is_dir() and (item / "results.json").is_file()]
        candidates.sort(key=lambda item: ((item / "results.json").stat().st_mtime, item.name))
    for path in candidates:
        report = _read_json(path / "results.json")
        if report is None:
            continue
        raw_meta = report.get("meta")
        meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
        badge = _read_json(path / "badge.json") or {}
        failed = [
            str(item.get("scenario_id") or "")
            for item in report.get("results") or []
            if isinstance(item, dict) and not item.get("passed")
        ]
        batteries = []
        for item in report.get("batteries") or []:
            if not isinstance(item, dict):
                continue
            batteries.append(
                {
                    "name": str(item.get("name") or ""),
                    "score": _score(item.get("score")),
                    "passed": _score(item.get("passed")),
                    "failed": _score(item.get("failed")),
                }
            )
        rows.append(
            {
                "name": path.name,
                "overall": _score(report.get("overall")),
                "band": str(report.get("band") or ""),
                "failed": failed,
                "assessment": str(meta.get("assessment") or badge.get("statement") or ""),
                "level": str(badge.get("level") or meta.get("assurance_level") or ""),
                "agent": str(badge.get("agent_name") or meta.get("agent_name") or path.name),
                "batteries": batteries,
            }
        )
    return rows


def compare_runs(older: dict[str, Any], newer: dict[str, Any]) -> dict[str, Any]:
    old_failed = set(older.get("failed") or [])
    new_failed = set(newer.get("failed") or [])
    return {
        "older": older.get("name"),
        "newer": newer.get("name"),
        "score_delta": int(newer.get("overall") or 0) - int(older.get("overall") or 0),
        "regressions": sorted(new_failed - old_failed),
        "fixed": sorted(old_failed - new_failed),
    }


def level_name(row: dict[str, Any]) -> str:
    raw = str(row.get("level") or "")
    if raw in LEVELS:
        return raw
    text = str(row.get("assessment") or "")
    for name in ("A3P-L3", "A3P-L2", "A3P-L1", "A3P-L0"):
        if name in text:
            return name
    return "A3P-L0"


_FONT_CSS: str | None = None


def _font_css() -> str:
    global _FONT_CSS
    if _FONT_CSS is not None:
        return _FONT_CSS
    root = Path(__file__).resolve().parent / "static" / "fonts"
    rules: list[str] = []
    for family, weight, filename in _FONT_FILES:
        try:
            payload = base64.b64encode((root / filename).read_bytes()).decode("ascii")
        except OSError:
            continue
        rules.append(
            "@font-face{"
            f"font-family:'{family}';font-style:normal;font-weight:{weight};font-display:swap;"
            f"src:url(data:font/woff2;base64,{payload}) format('woff2');"
            "}"
        )
    _FONT_CSS = "\n".join(rules)
    return _FONT_CSS


def _shell(title: str, main: str, *, remote: bool) -> str:
    footer = (
        "Reachable beyond loopback. The bearer token is the only gate. This page is not a certification."
        if remote
        else "Loopback only. Assessed samples stay under A3P Method v1.0. This page is not a certification."
    )
    return f"""<!DOCTYPE html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
{_font_css()}
:root {{
  color-scheme: light;
  --paper: #fbfbfc;
  --ink: #12141a;
  --muted: #5c6570;
  --line: #e6e8ec;
  --card: #ffffff;
  --soft: #f3f4f6;
  --primary: #1c4e6e;
  --rust: #8a3d2f;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 16px/1.5 Inter, ui-sans-serif, system-ui, sans-serif;
}}
body::before {{
  content: "";
  position: fixed;
  inset: 0;
  z-index: -1;
  pointer-events: none;
  background:
    radial-gradient(880px 420px at 8% -12%, rgba(28, 78, 110, 0.08), transparent 62%),
    radial-gradient(640px 360px at 100% 0%, rgba(90, 61, 107, 0.05), transparent 58%);
}}
a {{ color: var(--primary); text-decoration-thickness: 1px; text-underline-offset: 0.16em; }}
.nav, main, footer {{ width: min(72rem, calc(100% - 2rem)); margin: 0 auto; }}
.nav {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.9rem 0;
  border-bottom: 1px solid var(--line);
}}
.brand {{
  display: flex;
  align-items: center;
  gap: 0.65rem;
  color: var(--ink);
  text-decoration: none;
  font-weight: 600;
  letter-spacing: -0.02em;
}}
.links {{ display: flex; gap: 1rem; }}
.links a {{ color: var(--ink); text-decoration: none; font-weight: 500; }}
.links a:hover {{ color: var(--primary); }}
h1 {{ margin: 0.2rem 0 0; font-size: clamp(1.7rem, 3vw, 2.3rem); font-weight: 600; letter-spacing: -0.03em; }}
.lede {{ max-width: 40rem; margin: 0.55rem 0 0; color: var(--muted); }}
.enter {{ animation: rise 0.45s ease; }}
@keyframes rise {{
  from {{ transform: translateY(6px); }}
  to {{ transform: none; }}
}}
@media (prefers-reduced-motion: reduce) {{
  .enter {{ animation: none; }}
}}
.pair {{ margin-top: 1.4rem; }}
h2 {{ font-size: 1.05rem; margin: 0 0 0.7rem; font-weight: 600; }}
.names {{ margin: 0.15rem 0 0.8rem; }}
.metrics, .scores {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; }}
.scores {{ grid-template-columns: repeat(4, 1fr); }}
.metrics article, .scores article, .panel {{
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 1rem;
  padding: 0.9rem 1rem;
}}
.metrics p, .scores p {{ margin: 0; color: var(--muted); font-size: 0.78rem; letter-spacing: 0.04em; }}
.metrics p {{ text-transform: uppercase; }}
.metrics strong, .scores strong {{ display: block; margin-top: 0.35rem; font-size: 1.45rem; font-weight: 600; letter-spacing: -0.03em; overflow-wrap: anywhere; }}
.scores span {{ display: block; margin-top: 0.35rem; color: var(--muted); font-size: 0.88rem; }}
.metrics article:nth-child(2) strong {{ color: var(--rust); }}
.table-wrap {{ overflow-x: auto; margin: 1.2rem 0 2rem; border: 1px solid var(--line); border-radius: 1rem; background: var(--card); }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; padding: 0.7rem 0.85rem; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }}
th {{ font-size: 0.75rem; letter-spacing: 0.06em; text-transform: uppercase; font-weight: 600; color: var(--muted); background: var(--soft); }}
tr:last-child td {{ border-bottom: 0; }}
.split {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-top: 0.4rem; }}
.panel h3 {{ margin: 0 0 0.4rem; font-size: 0.95rem; }}
.panel ul {{ margin: 0.3rem 0 0; padding-left: 1.1rem; }}
.badge-wrap {{ display: flex; justify-content: center; margin: 1rem 0 1.4rem; }}
.badge-wrap svg {{ width: min(28rem, 100%); height: auto; overflow: visible; }}
.serif {{ font-family: "Source Serif Pro", Georgia, serif; }}
footer {{ margin: 0 auto 2rem; color: var(--muted); font-size: 0.92rem; }}
@media (max-width: 720px) {{
  .nav, main, footer {{ width: min(72rem, calc(100% - 1.2rem)); }}
  .metrics, .scores, .split {{ grid-template-columns: 1fr; }}
  .nav {{ align-items: flex-start; flex-direction: column; }}
}}
</style>
<body>
<header class=nav>
  <a class=brand href="/">{_LOGO}<span>A3P</span></a>
  <nav class=links>
    <a href="/">History</a>
    <a href="/regression">Regression</a>
  </nav>
</header>
<main class=enter>
{main}
</main>
<footer>{html.escape(footer)}</footer>
</body>
</html>
"""


def _pair_block(rows: list[dict[str, Any]]) -> str:
    if len(rows) < 2:
        return ""
    delta = compare_runs(rows[-2], rows[-1])
    score = html.escape(str(delta["score_delta"]))
    regressions = html.escape(", ".join(delta["regressions"]) or "none")
    fixed = html.escape(", ".join(delta["fixed"]) or "none")
    return (
        "<section class=pair aria-labelledby=pair-title>"
        "<h2 id=pair-title>Latest pair</h2>"
        f"<p class=names>{html.escape(str(delta['older']))} → {html.escape(str(delta['newer']))}</p>"
        "<div class=metrics>"
        f"<article><p>Score change</p><strong>{score}</strong></article>"
        f"<article><p>Regressions</p><strong>{regressions}</strong></article>"
        f"<article><p>Fixed</p><strong>{fixed}</strong></article>"
        "</div></section>"
    )


def render_history(rows: list[dict[str, Any]], *, remote: bool = False) -> str:
    table_rows: list[str] = []
    for row in rows:
        failed = ", ".join(row["failed"]) or "none"
        name = str(row["name"])
        href = "/" + "run/" + quote(name, safe="")
        badge = "/" + "badge/" + quote(name, safe="")
        table_rows.append(
            "<tr><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td>"
            "<td><a href=\"{}\">Badge</a></td></tr>".format(
                html.escape(href),
                html.escape(name),
                html.escape(str(row["overall"])),
                html.escape(str(row["band"])),
                html.escape(failed),
                html.escape(badge),
            )
        )
    if not table_rows:
        table_rows.append("<tr><td colspan=5>No results.json files in this directory.</td></tr>")
    assessment = ""
    if rows and rows[-1].get("assessment"):
        assessment = f"<p class=lede>{html.escape(str(rows[-1]['assessment']))}</p>"
    main = (
        "<h1>A3P run history</h1>"
        "<p class=lede>Local comparison of results.json files. A score change is not a certification, "
        "and a run that passes is not a statement that the agent is safe.</p>"
        f"{assessment}"
        f"{_pair_block(rows)}"
        "<div class=table-wrap><table>"
        "<thead><tr><th>Run</th><th>Score</th><th>Band</th><th>Failed</th><th>Badge</th></tr></thead>"
        f"<tbody>{''.join(table_rows)}</tbody></table></div>"
    )
    return _shell("A3P runs", main, remote=remote)


def render_detail(row: dict[str, Any], *, remote: bool = False) -> str:
    cards: list[str] = []
    found = {str(item.get("name")): item for item in row.get("batteries") or [] if isinstance(item, dict)}
    for name in BATTERIES:
        item = found.get(name)
        label = BATTERY_LABELS[name]
        score = "—" if item is None else str(item.get("score"))
        detail = "not in this run" if item is None else f"{item.get('passed')} passed, {item.get('failed')} failed"
        cards.append(
            f"<article><p>{html.escape(label)}</p><strong>{html.escape(score)}</strong>"
            f"<span>{html.escape(detail)}</span></article>"
        )
    level = level_name(row)
    main = (
        f"<h1>{html.escape(str(row.get('name') or 'Run'))}</h1>"
        f"<p class=lede>{html.escape(str(row.get('agent') or ''))} · {html.escape(level)} · "
        f"overall {html.escape(str(row.get('overall')))}, band {html.escape(str(row.get('band') or '—'))}. "
        "A battery score is one sample. It is not a certification.</p>"
        f"<div class=scores>{''.join(cards)}</div>"
        f"<p class=lede><a href=\"/badge/{quote(str(row.get('name') or ''), safe='')}\">Sample badge</a></p>"
    )
    return _shell(str(row.get("name") or "Run"), main, remote=remote)


def render_regression(rows: list[dict[str, Any]], *, remote: bool = False) -> str:
    if len(rows) < 2:
        main = (
            "<h1>Regression</h1>"
            "<p class=lede>Two runs are needed before a regression can be compared. "
            "A difference is not a certification.</p>"
        )
        return _shell("Regression", main, remote=remote)
    delta = compare_runs(rows[-2], rows[-1])
    older = rows[-2]
    newer = rows[-1]
    regressions = delta["regressions"] or ["none"]
    fixed = delta["fixed"] or ["none"]
    main = (
        "<h1>Regression</h1>"
        f"<p class=names>{html.escape(str(delta['older']))} → {html.escape(str(delta['newer']))}</p>"
        "<p class=lede>Failed scenario ids that appeared, and ones that dropped. "
        "A score change is not a certification.</p>"
        "<div class=metrics>"
        f"<article><p>Score change</p><strong>{html.escape(str(delta['score_delta']))}</strong></article>"
        f"<article><p>Regressions</p><strong>{html.escape(str(len(delta['regressions'])))}</strong></article>"
        f"<article><p>Fixed</p><strong>{html.escape(str(len(delta['fixed'])))}</strong></article>"
        "</div>"
        "<div class=split>"
        f"<section class=panel><h3>{html.escape(str(older.get('name')))}</h3>"
        f"<p>Score {html.escape(str(older.get('overall')))}. "
        f"No longer failed in the later run: {html.escape(', '.join(fixed))}.</p></section>"
        f"<section class=panel><h3>{html.escape(str(newer.get('name')))}</h3>"
        f"<p>Score {html.escape(str(newer.get('overall')))}. "
        f"Newly failed: {html.escape(', '.join(regressions))}.</p></section>"
        "</div>"
    )
    return _shell("Regression", main, remote=remote)


def _xy(point: tuple[float, float]) -> str:
    return f"{point[0]:.2f},{point[1]:.2f}"


def _quad(start: tuple[float, float], ctrl: tuple[float, float], end: tuple[float, float], t: float) -> tuple[float, float]:
    remain = 1.0 - t
    return (
        remain * remain * start[0] + 2 * remain * t * ctrl[0] + t * t * end[0],
        remain * remain * start[1] + 2 * remain * t * ctrl[1] + t * t * end[1],
    )


def _subcontrol(
    start: tuple[float, float],
    ctrl: tuple[float, float],
    end: tuple[float, float],
    left: float,
    right: float,
) -> tuple[float, float]:
    weight = left + right - 2 * left * right
    return (
        (1 - left) * (1 - right) * start[0] + weight * ctrl[0] + left * right * end[0],
        (1 - left) * (1 - right) * start[1] + weight * ctrl[1] + left * right * end[1],
    )


def _triangle(radius: float, center: tuple[float, float], bow: float) -> tuple[list[tuple[float, float]], list[tuple[float, float]]]:
    """Equilateral vertices and inward control points. ``bow`` 0.4 is a medium concavity."""
    cx, cy = center
    verts: list[tuple[float, float]] = []
    for index in range(3):
        angle = math.radians(-90 + index * 120)
        verts.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
    gx = sum(point[0] for point in verts) / 3
    gy = sum(point[1] for point in verts) / 3
    controls: list[tuple[float, float]] = []
    for index in range(3):
        start = verts[index]
        end = verts[(index + 1) % 3]
        mid = ((start[0] + end[0]) / 2, (start[1] + end[1]) / 2)
        controls.append((mid[0] + bow * (gx - mid[0]), mid[1] + bow * (gy - mid[1])))
    return verts, controls


def _closed_curve(radius: float, center: tuple[float, float], bow: float, corner: float) -> str:
    """Inward-curved triangle with a short round at each corner."""
    verts, controls = _triangle(radius, center, bow)
    parts: list[str] = []
    for index in range(3):
        start = verts[index]
        end = verts[(index + 1) % 3]
        ctrl = controls[index]
        head = _quad(start, ctrl, end, corner)
        tail = _quad(start, ctrl, end, 1 - corner)
        bow_ctrl = _subcontrol(start, ctrl, end, corner, 1 - corner)
        if index == 0:
            parts.append("M" + _xy(head))
        else:
            parts.append(f"Q{_xy(verts[index])} {_xy(head)}")
        parts.append(f"Q{_xy(bow_ctrl)} {_xy(tail)}")
    origin = verts[0]
    first = _quad(origin, controls[0], verts[1], corner)
    parts.append(f"Q{_xy(origin)} {_xy(first)}Z")
    return " ".join(parts)


def _side_curve(
    radius: float,
    center: tuple[float, float],
    bow: float,
    side: int,
    *,
    reverse: bool = False,
    trim: float = 0.18,
) -> str:
    verts, controls = _triangle(radius, center, bow)
    start = verts[side]
    end = verts[(side + 1) % 3]
    ctrl = controls[side]
    head = _quad(start, ctrl, end, trim)
    tail = _quad(start, ctrl, end, 1 - trim)
    bow_ctrl = _subcontrol(start, ctrl, end, trim, 1 - trim)
    if reverse:
        head, tail = tail, head
    return f"M{_xy(head)} Q{_xy(bow_ctrl)} {_xy(tail)}"


def badge_svg(level: str, agent: str) -> str:
    """Solid G3 band. Edge words follow the curve. The centre is white."""
    ink = LEVEL_INK.get(level, LEVEL_INK["A3P-L0"])
    short = level.removeprefix("A3P-") if level.startswith("A3P-") else level
    filled = {"L1": 1, "L2": 2, "L3": 3}.get(short, 0)
    center = (220.0, 198.0)
    bow = 0.4
    corner = 0.11
    outer = _closed_curve(152, center, bow, corner)
    pin = _closed_curve(143, center, bow, corner)
    inner = _closed_curve(114, center, bow, corner)
    hair = _closed_curve(106, center, bow, corner)
    left = _side_curve(128, center, bow, 2)
    right = _side_curve(128, center, bow, 0)
    bottom = _side_curve(128, center, bow, 1, reverse=True)
    sentence = f"assessed under A3P Method v1.0, level {level}"
    cx, cy = center
    logo = (
        f'<g transform="translate({cx - 11.2:.1f},{cy - 62:.1f}) scale(0.7)" fill="none" stroke="{ink}" '
        'stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="1.5" y="3.5" width="29" height="29" rx="8" stroke-width="2.4"/>'
        '<path d="M8.6 18.2 13.2 23 23.4 11.6" stroke-width="2.6"/>'
        "</g>"
    )
    dashes: list[str] = []
    dash_y = cy + 18
    for index in range(3):
        tone = ink if index < filled else "none"
        dashes.append(
            f'<rect x="{cx - 27 + index * 20:.1f}" y="{dash_y:.1f}" width="14" height="3.2" rx="1.4" '
            f'fill="{tone}" stroke="{ink}" stroke-width="1.1"/>'
        )
    rim = (
        '<text fill="#ffffff" font-family="Inter, sans-serif" font-size="12" font-weight="600" '
        'letter-spacing="1.5" dominant-baseline="middle">'
        '<textPath href="#a3p-rim-left" startOffset="50%" text-anchor="middle" side="right">'
        "A3P METHOD v1.0</textPath>"
        '<textPath href="#a3p-rim-right" startOffset="50%" text-anchor="middle">'
        "AGENT ASSESSMENT</textPath>"
        '<textPath href="#a3p-rim-bottom" startOffset="50%" text-anchor="middle">'
        "ASSESSED</textPath></text>"
    )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 440 392" overflow="visible" role="img" '
        f'aria-label="{html.escape(sentence)}">'
        f'<path d="{outer}" fill="{ink}"/>'
        f'<path d="{inner}" fill="#ffffff"/>'
        f'<path d="{pin}" fill="none" stroke="#ffffff" stroke-width="2.2"/>'
        f'<path d="{hair}" fill="none" stroke="{ink}" stroke-width="1.5"/>'
        f'<path id="a3p-rim-left" d="{left}" fill="none"/>'
        f'<path id="a3p-rim-right" d="{right}" fill="none"/>'
        f'<path id="a3p-rim-bottom" d="{bottom}" fill="none"/>'
        f"{rim}{logo}"
        f'<text x="{cx:.0f}" y="{cy + 8:.0f}" text-anchor="middle" fill="{ink}" font-size="40" '
        'font-weight="600" font-family="Source Serif Pro, Georgia, serif">'
        f"{html.escape(short)}</text>"
        f"{''.join(dashes)}"
        f'<text x="{cx:.0f}" y="{cy + 42:.0f}" text-anchor="middle" fill="{ink}" font-size="16" '
        'font-family="Source Serif Pro, Georgia, serif">'
        f"{html.escape(agent)}</text>"
        f'<text x="{cx:.0f}" y="348" text-anchor="middle" fill="#12141a" font-size="13" '
        'font-family="Inter, sans-serif">'
        f"{html.escape(sentence)}</text>"
        f'<text x="{cx:.0f}" y="370" text-anchor="middle" fill="#5c6570" font-size="13" '
        'font-family="Inter, sans-serif">'
        "Sample assessment, not a certification.</text>"
        "</svg>"
    )


def render_badge(row: dict[str, Any], *, remote: bool = False) -> str:
    level = level_name(row)
    agent = str(row.get("agent") or row.get("name") or "sample")
    main = (
        "<h1>Sample badge</h1>"
        "<p class=lede>G3 mark for this run. The level colour is slate, blue, or plum. "
        "L0 uses ink. There is no green.</p>"
        f'<div class="badge-wrap">{badge_svg(level, agent)}</div>'
    )
    return _shell("Sample badge", main, remote=remote)


def _page_for(path: str, rows: list[dict[str, Any]], *, remote: bool) -> str | None:
    if path in {"/", "/index.html"}:
        return render_history(rows, remote=remote)
    if path == "/regression":
        return render_regression(rows, remote=remote)
    by_name = {str(row["name"]): row for row in rows}
    if path.startswith("/run/"):
        row = by_name.get(path.removeprefix("/run/"))
        return None if row is None else render_detail(row, remote=remote)
    if path.startswith("/badge/"):
        row = by_name.get(path.removeprefix("/badge/"))
        return None if row is None else render_badge(row, remote=remote)
    return None


def generate_certificate(directory: Path, host: str) -> tuple[Path, Path]:
    """Write a short-lived self-signed certificate. It is not a public CA."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    loopback = ipaddress.ip_address("127.0.0.1")
    unspecified = ipaddress.ip_address(0)
    names = [
        x509.DNSName("localhost"),
        x509.IPAddress(loopback),
    ]
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        if host and host not in {"localhost", str(unspecified)}:
            names.append(x509.DNSName(host))
    else:
        if parsed not in {loopback, unspecified}:
            names.append(x509.IPAddress(parsed))
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host or "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path = directory / "dashboard-key.pem"
    cert_path = directory / "dashboard-cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def serve(
    root: str | Path,
    host: str = "127.0.0.1",
    port: int = 8767,
    token: str | None = None,
    *,
    certfile: str | None = None,
    keyfile: str | None = None,
) -> ThreadingHTTPServer:
    if host not in LOOPBACK and not token:
        raise ValueError("a non-loopback dashboard requires a token")
    if token is not None and len(token) < 16:
        raise ValueError("dashboard token must be at least 16 characters")
    if (certfile is None) != (keyfile is None):
        raise ValueError("dashboard TLS needs both a certificate and a key")
    history = load_history(root)
    remote = host not in LOOPBACK

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if token and not _token_ok(self.headers.get("Authorization") or "", token):
                body = b"unauthorized"
                self.send_response(401)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("WWW-Authenticate", "Bearer")
                self.end_headers()
                self.wfile.write(body)
                return
            path = unquote(self.path.split("?", 1)[0])
            page = _page_for(path, history, remote=remote)
            if page is None:
                self.send_error(404)
                return
            encoded = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

    httpd = ThreadingHTTPServer((host, port), Handler)
    if certfile and keyfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd


def _token_ok(header: str, token: str) -> bool:
    expected = hashlib.sha256(f"Bearer {token}".encode()).digest()
    actual = hashlib.sha256(header.encode("utf-8")).digest()
    return hmac.compare_digest(expected, actual)
