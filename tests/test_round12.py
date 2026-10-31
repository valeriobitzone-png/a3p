"""Dashboard pages, G3 badge, and screenshots at 1440 and 390."""

from __future__ import annotations

import os
import json
import threading
import time
from pathlib import Path

import pytest

from a3p.dashboard import (
    badge_svg,
    level_name,
    load_history,
    render_badge,
    render_detail,
    render_regression,
    serve,
)


def _runs(tmp_path: Path) -> Path:
    older = tmp_path / "zzz-old"
    newer = tmp_path / "aaa-new"
    older.mkdir()
    newer.mkdir()
    (older / "results.json").write_text(
        json.dumps(
            {
                "overall": 80,
                "band": "review",
                "batteries": [
                    {"name": "phantom", "score": 90, "passed": 9, "failed": 1},
                    {"name": "injection", "score": 70, "passed": 7, "failed": 3},
                    {"name": "permission", "score": 80, "passed": 8, "failed": 2},
                    {"name": "leakage", "score": 60, "passed": 6, "failed": 4},
                ],
                "results": [{"scenario_id": "kept", "passed": False}],
                "meta": {"agent_name": "older-agent", "assurance_level": "A3P-L1"},
            }
        ),
        encoding="utf-8",
    )
    time.sleep(0.05)
    (newer / "results.json").write_text(
        json.dumps(
            {
                "overall": 40,
                "band": "fail",
                "batteries": [
                    {"name": "phantom", "score": 50, "passed": 5, "failed": 5},
                    {"name": "injection", "score": 40, "passed": 4, "failed": 6},
                    {"name": "permission", "score": 30, "passed": 3, "failed": 7},
                    {"name": "leakage", "score": 20, "passed": 2, "failed": 8},
                ],
                "results": [{"scenario_id": "regressed", "passed": False}],
                "meta": {
                    "agent_name": "newer-agent",
                    "assessment": "assessed under A3P Method v1.0, level A3P-L2",
                },
            }
        ),
        encoding="utf-8",
    )
    (newer / "badge.json").write_text(
        json.dumps({"level": "A3P-L2", "agent_name": "newer-agent", "statement": "assessed under A3P Method v1.0, level A3P-L2"}),
        encoding="utf-8",
    )
    return tmp_path


def test_badge_is_g3_and_has_no_green() -> None:
    svg = badge_svg("A3P-L2", "sample agent")
    assert svg.count("<textPath ") == 3
    assert svg.count('fill="#ffffff"') >= 1
    assert 'fill="#1c4e6e"' in svg
    assert "Q" in svg
    assert "A3P METHOD v1.0" in svg
    assert "AGENT ASSESSMENT" in svg
    assert "ASSESSED" in svg
    assert ">L2</text>" in svg
    assert svg.count('width="14" height="3.2" rx="1.4" fill="#1c4e6e"') == 2
    assert svg.count('width="14" height="3.2" rx="1.4" fill="none"') == 1
    assert "#5f6f7f" in badge_svg("A3P-L1", "a")
    assert badge_svg("A3P-L1", "a").count('width="14" height="3.2" rx="1.4" fill="#5f6f7f"') == 1
    assert badge_svg("A3P-L3", "a").count('width="14" height="3.2" rx="1.4" fill="#5a3d6b"') == 3
    assert badge_svg("A3P-L0", "a").count('width="14" height="3.2" rx="1.4" fill="#12141a"') == 0
    assert "assessed under A3P Method v1.0, level A3P-L2" in svg
    assert "Sample assessment, not a certification." in svg
    assert "Source Serif Pro" in svg
    assert "Inter" in svg
    lowered = svg.lower()
    assert "#1d6b45" not in lowered
    assert "green" not in lowered
    assert level_name({"level": "", "assessment": "level A3P-L3"}) == "A3P-L3"
    assert level_name({}) == "A3P-L0"


def test_pages_list_batteries_and_the_regression(tmp_path: Path) -> None:
    root = _runs(tmp_path)
    rows = load_history(root)
    assert rows[1]["agent"] == "newer-agent"
    assert rows[1]["level"] == "A3P-L2"
    detail = render_detail(rows[1])
    assert "Phantom (false ok)" in detail
    assert "Injection" in detail
    assert "Permission" in detail
    assert "Leakage" in detail
    assert "not a certification" in detail.lower()
    regression = render_regression(rows)
    assert "zzz-old → aaa-new" in regression
    assert "regressed" in regression
    empty = render_regression(rows[:1])
    assert "Two runs are needed" in empty
    badge = render_badge(rows[1])
    assert "A3P-L2" in badge
    assert "newer-agent" in badge
    assert badge.count("assessed under A3P Method v1.0, level A3P-L2") == 2
    assert badge.count("Sample assessment, not a certification.") == 1
    assert "<p class=lede>assessed" not in badge
    missing = render_detail({"name": "solo", "overall": 0, "band": "", "agent": "solo", "batteries": []})
    assert "not in this run" in missing


def _settle_and_assert_opaque(page) -> None:
    """Wait until CSS animations finish, then require the heading to be fully opaque."""
    opaque = page.evaluate(
        """() => Promise.all(
            document.getAnimations().map((animation) => animation.finished.catch(() => undefined))
        ).then(() => {
            const heading = document.querySelector('h1');
            if (!heading) return { opacity: 0, blur: true, color: '' };
            let node = heading;
            let opacity = 1;
            let blur = false;
            while (node) {
                const style = getComputedStyle(node);
                opacity *= Number(style.opacity);
                if ((style.filter || 'none').includes('blur')) blur = true;
                node = node.parentElement;
            }
            return { opacity, blur, color: getComputedStyle(heading).color };
        })"""
    )
    assert opaque["blur"] is False
    assert opaque["opacity"] == 1
    assert opaque["color"] == "rgb(18, 20, 26)"


def test_routes_and_viewports(tmp_path: Path) -> None:
    root = _runs(tmp_path)
    server = serve(root, port=0)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    playwright_sync = pytest.importorskip("playwright.sync_api")
    shots: dict[str, Path] = {}
    try:
        with playwright_sync.sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            for width, suffix in ((1440, "1440"), (390, "390")):
                page = browser.new_page(viewport={"width": width, "height": 900})
                page.goto(f"http://127.0.0.1:{port}/", wait_until="domcontentloaded")
                page.get_by_role("heading", name="A3P run history").wait_for()
                _settle_and_assert_opaque(page)
                assert "zzz-old → aaa-new" in page.inner_text("body")
                shots[f"dashboard-history-{suffix}.png"] = tmp_path / f"history-{suffix}.png"
                page.screenshot(path=str(shots[f"dashboard-history-{suffix}.png"]), full_page=True)
                page.get_by_role("link", name="aaa-new").click()
                page.get_by_role("heading", name="aaa-new").wait_for()
                _settle_and_assert_opaque(page)
                assert "Phantom (false ok)" in page.inner_text("body")
                shots[f"dashboard-run-{suffix}.png"] = tmp_path / f"run-{suffix}.png"
                page.screenshot(path=str(shots[f"dashboard-run-{suffix}.png"]), full_page=True)
                page.goto(f"http://127.0.0.1:{port}/regression", wait_until="domcontentloaded")
                page.get_by_role("heading", name="Regression").wait_for()
                _settle_and_assert_opaque(page)
                assert "regressed" in page.inner_text("body")
                shots[f"dashboard-regression-{suffix}.png"] = tmp_path / f"regression-{suffix}.png"
                page.screenshot(path=str(shots[f"dashboard-regression-{suffix}.png"]), full_page=True)
                page.goto(f"http://127.0.0.1:{port}/badge/aaa-new", wait_until="domcontentloaded")
                page.get_by_role("heading", name="Sample badge").wait_for()
                page.evaluate("() => document.fonts.ready")
                _settle_and_assert_opaque(page)
                assert "Sample assessment, not a certification." in page.inner_text("body")
                assert "A3P METHOD v1.0" in page.inner_text("body")
                assert page.inner_text("body").count("assessed under A3P Method v1.0, level A3P-L2") == 1
                paint = page.evaluate(
                    """() => {
                        const svg = document.querySelector('.badge-wrap svg');
                        const xml = new XMLSerializer().serializeToString(svg);
                        const url = URL.createObjectURL(new Blob([xml], {type: 'image/svg+xml'}));
                        const box = svg.viewBox.baseVal;
                        return new Promise((resolve, reject) => {
                            const img = new Image();
                            img.onload = () => {
                                const canvas = document.createElement('canvas');
                                canvas.width = box.width;
                                canvas.height = box.height;
                                const ctx = canvas.getContext('2d');
                                ctx.drawImage(img, 0, 0, box.width, box.height);
                                const data = ctx.getImageData(0, 0, box.width, box.height).data;
                                let blue = 0;
                                let white = 0;
                                for (let i = 0; i < data.length; i += 16) {
                                    const r = data[i], g = data[i + 1], b = data[i + 2], a = data[i + 3];
                                    if (a < 200) continue;
                                    if (r < 55 && g > 55 && g < 120 && b > 80 && b < 150) blue += 1;
                                    if (r > 248 && g > 248 && b > 248) white += 1;
                                }
                                URL.revokeObjectURL(url);
                                resolve({blue, white});
                            };
                            img.onerror = () => reject(new Error('badge svg did not paint'));
                            img.src = url;
                        });
                    }"""
                )
                assert paint["blue"] > 80
                assert paint["white"] > 80
                shots[f"dashboard-badge-{suffix}.png"] = tmp_path / f"badge-{suffix}.png"
                page.screenshot(path=str(shots[f"dashboard-badge-{suffix}.png"]), full_page=True)
                overflow = page.evaluate(
                    "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
                )
                assert overflow < 8
            missing = page.goto(f"http://127.0.0.1:{port}/missing", wait_until="commit")
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
    assert missing is not None and missing.status == 404
    artifacts = Path(os.environ.get("A3P_ARTIFACTS_DIR", "artifacts"))
    for name, shot in shots.items():
        assert shot.stat().st_size > 1000
        try:
            artifacts.mkdir(parents=True, exist_ok=True)
            (artifacts / name).write_bytes(shot.read_bytes())
        except OSError:
            pass
