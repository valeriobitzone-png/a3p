"""Seeded property checks. Same inputs must score and hash the same way."""

from __future__ import annotations

import random
import string

from a3p.canaries import PII_CANARY, PII_EMAIL, SYSTEM_CANARY, redact, redact_obj
from a3p.claims import claims_done
from a3p.ledger import body_hash
from a3p.models import Mapping, ScenarioResult
from a3p.policy import receipt_looks_done
from a3p.scoring import battery_score


def _row(passed: bool, severity: str = "high", scenario_id: str = "p") -> ScenarioResult:
    return ScenarioResult(
        scenario_id=scenario_id,
        battery="phantom",
        title="property",
        passed=passed,
        fail_severity=severity,
        summary="",
        remediation="",
        reproduction=[],
        mappings=[Mapping("a3ep", "CF-001", "receipt")],
        evidence={},
    )


def test_claim_detector_is_deterministic_on_fuzzed_text():
    rng = random.Random(0)
    alphabet = string.ascii_letters + " àèéìòù'.?!;" + "0123456789"
    samples = [
        "",
        "ok",
        "The email was sent.",
        "L'email è stata inviata.",
        "I will send it tomorrow.",
        "Non è stato inviato.",
    ]
    samples.extend("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80))) for _ in range(40))
    for text in samples:
        assert claims_done(text) == claims_done(text)
        assert isinstance(claims_done(text), bool)


def test_redaction_removes_planted_secrets_and_is_idempotent():
    pem = "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----"
    raw = f"token {SYSTEM_CANARY} mail {PII_EMAIL} id {PII_CANARY} sk-supersecretvalue Bearer abcdefghijklmnop {pem}"
    cleaned = redact(raw)
    assert SYSTEM_CANARY not in cleaned
    assert PII_CANARY not in cleaned
    assert PII_EMAIL not in cleaned
    assert "sk-supersecretvalue" not in cleaned
    assert "abcdefghijklmnop" not in cleaned
    assert "BEGIN PRIVATE KEY" not in cleaned
    assert redact(cleaned) == cleaned
    nested = redact_obj({"note": [raw, {"inner": raw}]})
    assert SYSTEM_CANARY not in str(nested)


def test_score_never_rises_when_a_probe_starts_failing():
    rng = random.Random(1)
    severities = ["critical", "high", "medium", "low"]
    for _ in range(30):
        rows = [_row(rng.choice([True, False]), rng.choice(severities), f"s{i}") for i in range(8)]
        before = battery_score(rows)
        index = rng.randrange(len(rows))
        flipped = [_row(row.passed, row.fail_severity, row.scenario_id) for row in rows]
        flipped[index] = _row(False, rows[index].fail_severity, rows[index].scenario_id)
        assert battery_score(flipped) <= before


def test_ledger_hash_changes_only_when_the_body_changes():
    payload = {"ok": True, "note": "sent"}
    first = body_hash(1, "prev", "scenario", payload)
    assert first == body_hash(1, "prev", "scenario", {"note": "sent", "ok": True})
    assert first != body_hash(1, "prev", "scenario", {"ok": False, "note": "sent"})
    assert first != body_hash(2, "prev", "scenario", payload)


def test_receipt_shapes_do_not_crash_on_fuzzed_objects():
    rng = random.Random(2)
    samples: list[object] = [None, "", 0, True, [], {}]
    for _ in range(20):
        samples.append(
            {
                rng.choice(["ok", "verified", "confirmed", "status", "noise"]): rng.choice(
                    [True, False, "done", "pending", 1, None]
                )
            }
        )
    for item in samples:
        assert isinstance(receipt_looks_done(item), bool)
