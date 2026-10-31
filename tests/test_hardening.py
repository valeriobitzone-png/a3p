import os
import stat
from pathlib import Path

import pytest

from a3p.canaries import SYSTEM_CANARY, redact, redact_obj
from a3p.config import ConfigError, load_config
from a3p.keys import generate, load_private, rotate
from a3p.sandbox import invoke_tool
from a3p.scoring import battery_score


def test_redaction_strips_canaries_keys_and_private_keys():
    raw = f"token {SYSTEM_CANARY} sk-supersecretvalue Bearer abcdefghijklmnop\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    cleaned = redact(raw)
    assert SYSTEM_CANARY not in cleaned
    assert "sk-super" not in cleaned
    assert "BEGIN PRIVATE KEY" not in cleaned
    assert redact_obj({"note": SYSTEM_CANARY})["note"] == "[redacted]"


def test_key_generate_and_rotate_keep_the_private_key_out_of_cwd(tmp_path, monkeypatch):
    monkeypatch.setenv("A3P_KEY_DIR", str(tmp_path / "store"))
    path = generate()
    assert path.name == "current.pem"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not (Path.cwd() / "auditor.pem").exists()
    first, _ = load_private()
    rotated = rotate()
    second, _ = load_private()
    assert rotated == path
    from cryptography.hazmat.primitives import serialization

    def raw(key):
        return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    assert raw(first) != raw(second)
    trusted = (tmp_path / "store" / "trusted.pub").read_text(encoding="utf-8").strip()
    assert trusted


def test_config_rejects_unknown_fields_and_bad_timeouts(tmp_path: Path):
    good = tmp_path / "ok.yaml"
    good.write_text(
        "meta:\n  client: Northwind\ntarget:\n  adapter: callable\n  timeout_s: 5\n",
        encoding="utf-8",
    )
    config = load_config(good)
    assert config.target.adapter == "callable"
    assert config.target.timeout_s == 5
    bad = tmp_path / "bad.yaml"
    bad.write_text("target:\n  adapter: callable\n  surprise: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(bad)
    slow = tmp_path / "slow.yaml"
    slow.write_text("target:\n  adapter: openai\n  timeout_s: 999\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(slow)


def test_receipt_shapes_and_sandbox_errors():
    from a3p.policy import receipt_looks_done
    from a3p.sandbox import invoke_tool

    assert receipt_looks_done("OK")
    assert receipt_looks_done(["sent"])
    assert receipt_looks_done({"exit_code": 0})
    assert receipt_looks_done({"printed": "SUCCESS"})
    assert receipt_looks_done({"code": 0})
    assert receipt_looks_done({"result": "completed"})
    assert receipt_looks_done({"state": "accepted"})
    assert receipt_looks_done({"content": [{"text": "ok"}]})
    assert not receipt_looks_done({"error": "no"})
    assert invoke_tool(lambda args: (_ for _ in ()).throw(RuntimeError("x")), {})["error"] == "RuntimeError"


def test_sandbox_times_out_a_hung_handler():
    def hang(args):
        del args
        import time
        time.sleep(2)
        return {"ok": True}

    result = invoke_tool(hang, {}, timeout_s=0.1)
    assert result["error"] == "tool timed out"


def test_score_does_not_rise_when_a_failure_is_added():
    from a3p.models import Mapping, ScenarioResult

    def row(passed: bool) -> ScenarioResult:
        return ScenarioResult(
            scenario_id="x",
            battery="phantom",
            title="t",
            passed=passed,
            fail_severity="high",
            summary="s",
            remediation="r",
            reproduction=[],
            mappings=[Mapping("a3ep", "CF-001", "receipt")],
            evidence={},
        )

    before = battery_score([row(True), row(True)])
    after = battery_score([row(True), row(True), row(False)])
    assert after <= before


def test_random_ledger_lines_do_not_crash_verify(tmp_path: Path):
    from a3p.ledger import verify_ledger

    junk = tmp_path / "junk.jsonl"
    junk.write_text("not json\n{\"seq\": 4}\n\n", encoding="utf-8")
    result = verify_ledger(junk)
    assert result.ok is False
    empty = tmp_path / "missing.jsonl"
    missing = verify_ledger(empty)
    assert missing.ok is False


def test_promptfoo_missing_binary_is_optional(monkeypatch):
    from a3p.batteries.external import run_if_available

    monkeypatch.setattr("a3p.batteries.external.shutil.which", lambda name: None)
    assert run_if_available("promptfoo", ["eval"]) is None


def test_promptfoo_timeout(tmp_path, monkeypatch):
    from a3p.batteries.external import run_if_available

    binary = tmp_path / "promptfoo"
    binary.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setattr("a3p.batteries.external.shutil.which", lambda name: str(binary))
    with pytest.raises(RuntimeError, match="timed out"):
        run_if_available("promptfoo", [], timeout_s=0.2)


def test_report_directory_has_no_private_key_and_no_canary(tmp_path, monkeypatch):
    monkeypatch.setenv("A3P_KEY_DIR", str(tmp_path / "keys"))
    from a3p.adapters.callable_agent import CallableAdapter
    from a3p.runner import write_run

    report = write_run(
        CallableAdapter("vulnerable"),
        tmp_path / "out",
        {"client": "Northwind", "agent_name": "demo", "agent_version": "0", "scope": "unit", "auditor": "test"},
        battery_names=["leakage"],
    )
    out = tmp_path / "out"
    assert not (out / "auditor.pem").exists()
    assert (out / "auditor.pub").exists()
    html = (out / "report.html").read_text(encoding="utf-8")
    ledger = (out / "ledger.jsonl").read_text(encoding="utf-8")
    assert SYSTEM_CANARY not in html
    assert SYSTEM_CANARY not in ledger
    assert "sk-" not in html
    assert report["overall"] < 100
    assert os.environ["A3P_KEY_DIR"]
