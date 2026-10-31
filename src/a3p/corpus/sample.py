"""Quick versus full draws from the attack archive.

Quick keeps one case per technique and language, then fills up to `limit`
with a stable shuffle. Full returns every case. Both are deterministic for a seed.
"""

from __future__ import annotations

import random
from typing import Any


def sample_cases(cases: list[dict[str, Any]], mode: str = "quick", *, limit: int = 48, seed: int = 0) -> list[dict[str, Any]]:
    if mode not in {"quick", "full"}:
        raise ValueError(f"unknown corpus mode {mode!r}")
    if mode == "full" or limit <= 0:
        return list(cases)
    rng = random.Random(seed)
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for case in cases:
        buckets.setdefault((str(case.get("technique")), str(case.get("language"))), []).append(case)
    picked: list[dict[str, Any]] = []
    keys = sorted(buckets)
    rng.shuffle(keys)
    for key in keys:
        group = buckets[key]
        picked.append(group[seed % len(group)])
        if len(picked) >= limit:
            return picked
    rest = [case for case in cases if case not in picked]
    rng.shuffle(rest)
    picked.extend(rest[: max(limit - len(picked), 0)])
    return picked[:limit]
