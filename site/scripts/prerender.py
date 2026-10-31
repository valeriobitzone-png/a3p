"""Write the rendered pages into dist so the scores are in the HTML without JavaScript."""

from __future__ import annotations

import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("playwright is not installed; leaving the client-rendered HTML")
    sys.exit(0)

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
PORT = 43149
PAGES = ("/", "/verify/", "/results/")


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIST), **kwargs)

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            for path in PAGES:
                page.goto(f"http://127.0.0.1:{PORT}{path}", wait_until="networkidle")
                page.wait_for_selector("h1")
                html = page.content()
                target = DIST / "index.html" if path == "/" else DIST / path.strip("/") / "index.html"
                target.write_text(html, encoding="utf-8")
                print("prerendered", target.relative_to(DIST))
            browser.close()
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
