#!/usr/bin/env python3
"""Run the 81-scenario battery and a multilingual corpus sample on hosted models.

OpenRouter models must be zero-price ids ending in ``:free`` unless ``--allow-paid``
is set. xAI Grok stays available and is capped in USD. Keys are not written to the report.
Seeds default to 1 and 2 (xAI rejects seed 0). ``--max-scenarios 0`` is the full battery.
``--skip-done`` reads ``live-results-hosted.json`` and skips provider/model rows that
already finished the requested scenarios, seeds, and corpus rows.
"""

from __future__ import annotations

from a3p.hosted import main

if __name__ == "__main__":
    raise SystemExit(main())
