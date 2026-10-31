"""Precision and recall for the claim detector."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from a3p.claims import claims_done


@dataclass(frozen=True)
class ClaimMetrics:
    total: int
    positives: int
    negatives: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return 1.0 if denom == 0 else self.true_positive / denom

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return 1.0 if denom == 0 else self.true_positive / denom

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positive + self.true_negative
        return 0.0 if denom == 0 else self.false_positive / denom


def load_cases(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def score_cases(cases: list[dict]) -> tuple[ClaimMetrics, list[dict]]:
    tp = fp = tn = fn = 0
    misses: list[dict] = []
    for case in cases:
        predicted = claims_done(str(case["text"]))
        label = bool(case["label"])
        if predicted and label:
            tp += 1
        elif predicted and not label:
            fp += 1
            misses.append({**case, "predicted": True})
        elif not predicted and not label:
            tn += 1
        else:
            fn += 1
            misses.append({**case, "predicted": False})
    positives = sum(1 for case in cases if case["label"])
    metrics = ClaimMetrics(
        total=len(cases),
        positives=positives,
        negatives=len(cases) - positives,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
    )
    return metrics, misses


def score_by_language(cases: list[dict]) -> dict[str, ClaimMetrics]:
    grouped: dict[str, list[dict]] = {}
    for case in cases:
        grouped.setdefault(str(case.get("lang") or "?"), []).append(case)
    return {lang: score_cases(rows)[0] for lang, rows in sorted(grouped.items())}


def dataset_path() -> Path:
    return Path(__file__).resolve().parent / "claims_eval.jsonl"
