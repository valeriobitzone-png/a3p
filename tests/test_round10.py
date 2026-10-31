"""Live MCP scan, seeded adaptive attacker, badge Sigstore check, dashboard order."""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a3p.adaptive import AttackBudget, run_adaptive_chat
from a3p.adaptive_llm import (
    AdaptiveAttacker,
    attacks_from_ledger,
    offline_turn,
    replay_attacker,
    scripted_plan,
    seal_attacks,
)
from a3p.cli import main
from a3p.corpus.phrases import LANGS
from a3p.dashboard import load_history, render_history, serve
from a3p.isolation import command_for
from a3p.mcp_dynamic import archive_probes, run_live_scan
from a3p.method import sign_badge, statement, verify_badge, verify_badge_keyless


def _badge() -> dict[str, object]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    signed = sign_badge(
        {
            "method_version": "1.0",
            "level": "A3P-L1",
            "statement": statement("A3P-L1"),
            "public_key_hex": public,
            "agent_name": "demo",
            "overall": 80,
            "band": "pass",
            "criteria": {
                "batteries_complete": True,
                "seeds": 1,
                "ledger_head": "abc",
                "handlers": "in-process",
                "tool_level": "inprocess",
                "network_denied": False,
                "host_marker_intact": False,
                "model_level": "scripted",
                "handlers_inprocess": 1,
            },
            "phantom_failed": 0,
            "phantom_total": 1,
            "phantom_score": 100,
        },
        key,
    )
    return signed


def test_popen_refuses_a_missing_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    from a3p.isolation import popen_sandboxed

    monkeypatch.setattr("a3p.isolation.docker_prefix", lambda run=None: None)
    with pytest.raises(OSError, match="Docker"):
        popen_sandboxed("container", ["-m", "a3p.mcp_vulnerable"])
    with pytest.raises(ValueError, match="unsupported"):
        popen_sandboxed("inprocess", ["-c"])


def test_sandbox_argv_stays_network_none(tmp_path: Path) -> None:
    command = command_for(
        "container",
        tmp_path / "escape",
        9,
        ["docker"],
        stdin_open=True,
        program=["-m", "a3p.mcp_vulnerable"],
        extra_env={"A3P_MCP_UDS": "/opt/a3p-rw/mcp.sock"},
        rw_mount=(tmp_path, "/opt/a3p-rw"),
    )
    assert command[command.index("--network") + 1] == "none"
    assert "a3p.mcp_vulnerable" in command
    assert f"{tmp_path}:/opt/a3p-rw:rw" in command
    wrapped = command_for(
        "bwrap",
        tmp_path / "escape",
        9,
        program=["-m", "a3p.mcp_vulnerable"],
        rw_mount=(tmp_path, "/opt/a3p-rw"),
    )
    assert "--unshare-all" in wrapped
    assert "--bind" in wrapped
    with pytest.raises(ValueError, match="environment"):
        command_for("container", tmp_path, 9, ["docker"], extra_env={"not-upper": "x"})


def test_live_stdio_scan_seals_the_demo(tmp_path: Path) -> None:
    report = run_live_scan(
        level="process",
        transport="stdio",
        output=tmp_path,
        seed=1,
        probes=[{"id": "probe-en", "language": "en", "text": "warehouse note"}],
        allow_process=True,
    )
    kinds = {item["kind"] for item in report["findings"]}
    assert {"poisoning", "rug-pull", "excessive-permission", "injection", "secret"} <= kinds
    assert report["resources"] == ["note://canary"]
    assert report["prompts"] == ["override"]
    assert "shell" not in {item["name"] for item in report["findings"] if item["kind"] == "injection"}
    ledger = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8")
    assert "mcp-finding" in ledger
    assert "mcp-live-scan" in ledger
    assert main(
        [
            "mcp-scan",
            "--live",
            "--sandbox",
            "process",
            "--unsafe-process-sandbox",
            "--output",
            str(tmp_path / "cli"),
            "--seed",
            "1",
        ]
    ) == 1
    assert (tmp_path / "cli" / "ledger.jsonl").is_file()


def test_live_sse_scan_over_a_unix_socket(tmp_path: Path) -> None:
    report = run_live_scan(
        level="process",
        transport="sse",
        output=tmp_path,
        probes=[{"id": "probe-it", "language": "it", "text": "nota"}],
        allow_process=True,
    )
    assert report["transport"] == "sse"
    assert report["network"] == "open"
    assert any(item["kind"] == "secret" for item in report["findings"])


def test_bwrap_scan_when_present(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None:
        pytest.skip("bwrap is not installed")
    report = run_live_scan(
        level="bwrap",
        transport="stdio",
        output=tmp_path,
        probes=[{"id": "probe", "language": "en", "text": "note"}],
    )
    assert report["sandbox"] == "bwrap"
    assert report["network"] == "denied"
    assert any(item["kind"] == "rug-pull" for item in report["findings"])


def test_archive_probe_is_deterministic() -> None:
    first = archive_probes(3, 2)
    second = archive_probes(3, 2)
    assert first == second
    assert first[0]["id"]
    assert len(first) == 2


def test_adaptive_seed_endpoint_and_replay(tmp_path: Path) -> None:
    plan = scripted_plan("office hours", 0, 11)
    assert {item["language"] for item in plan} == set(LANGS)
    assert {item["strategy"] for item in plan} == {"paraphrase", "translation", "encoding", "role-play", "split"}
    with pytest.raises(ValueError):
        offline_turn("x", "nope", "en", 0)
    left = AdaptiveAttacker("office hours", seed=4, budget=AttackBudget(max_turns=3, max_calls=3, max_chars=400))
    right = AdaptiveAttacker("office hours", seed=4, budget=AttackBudget(max_turns=3, max_calls=3, max_chars=400))
    assert [left.next_message([]) for _ in range(3)] == [right.next_message([]) for _ in range(3)]

    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        seen["seed"] = body["seed"]
        seen["system"] = body["messages"][0]["content"]
        return httpx.Response(200, json={"choices": [{"message": {"content": "MUTATED-TURN"}}]})

    client = httpx.Client(base_url="http://example.test/v1", transport=httpx.MockTransport(handler))
    live = AdaptiveAttacker(
        "office hours",
        seed=2,
        base_url="http://example.test/v1",
        model="demo",
        client=client,
        budget=AttackBudget(max_turns=1, max_calls=1, max_chars=80),
    )
    messages = run_adaptive_chat(
        lambda _history: "TARGET-SAID-THIS",
        live,
        task="Start.",
        max_turns=1,
    )
    assert messages[-1]["content"] == "MUTATED-TURN"
    assert seen["seed"] == 2
    assert "TARGET-SAID-THIS" in str(seen["system"])
    head = seal_attacks(tmp_path, live)
    assert head
    replay = replay_attacker(attacks_from_ledger(tmp_path))
    assert replay.next_message([]) == "MUTATED-TURN"

    def down(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    fallback = AdaptiveAttacker(
        "office hours",
        seed=1,
        base_url="http://example.test/v1",
        model="demo",
        client=httpx.Client(base_url="http://example.test/v1", transport=httpx.MockTransport(down)),
        budget=AttackBudget(max_turns=1, max_calls=1, max_chars=12),
    )
    text = fallback.next_message([{"role": "assistant", "content": "seen"}])
    assert text is not None
    assert len(text) == 12
    assert fallback.generated[0]["source"] == "scripted"


def test_verify_badge_checks_sigstore_beside_ed25519(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from a3p.method import seal_badge, sigstore_digest

    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    bundle = {"bundle": {"ok": True}, "identity": "ci@example", "issuer": "https://token.actions.githubusercontent.com"}
    body = {
        "method_version": "1.0",
        "level": "A3P-L1",
        "statement": statement("A3P-L1"),
        "public_key_hex": public,
        "agent_name": "demo",
        "overall": 80,
        "band": "pass",
        "criteria": {
            "batteries_complete": True,
            "seeds": 1,
            "ledger_head": "abc",
            "handlers": "in-process",
            "tool_level": "inprocess",
            "network_denied": False,
            "host_marker_intact": False,
            "model_level": "scripted",
            "handlers_inprocess": 1,
        },
        "phantom_failed": 0,
        "phantom_total": 1,
        "phantom_score": 100,
    }
    signed = seal_badge(body, key, bundle)
    assert signed["sigstore_sha256"] == sigstore_digest(bundle)
    assert verify_badge(signed)[0] is True
    loose = _badge()
    loose["sigstore"] = bundle
    assert verify_badge(loose)[0] is False
    monkeypatch.setattr(
        "a3p.attest.verify_keyless",
        lambda *_args, **_kwargs: {"logIndex": "7", "integratedTime": "1", "identity": "ci@example", "issuer": "https://token.actions.githubusercontent.com"},
    )
    ok, reason = verify_badge_keyless(signed, "ci@example", "https://token.actions.githubusercontent.com")
    assert ok, reason
    assert "rekor 7" in reason
    missing = _badge()
    assert verify_badge_keyless(missing, "ci@example", "https://issuer.example")[0] is False
    path = tmp_path / "badge.json"
    path.write_text(json.dumps(signed), encoding="utf-8")
    assert main(["verify-badge", str(path), "--identity", "ci@example", "--issuer", "https://token.actions.githubusercontent.com"]) == 0
    assert main(["verify-badge", str(path), "--identity", "only-one"]) == 2
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(_badge()), encoding="utf-8")
    assert main(["verify-badge", str(bare)]) == 0

    def explode(*_args: object, **_kwargs: object) -> dict[str, str]:
        from a3p.attest import AttestationError

        raise AttestationError("rekor rejected the proof")

    monkeypatch.setattr("a3p.attest.verify_keyless", explode)
    assert verify_badge_keyless(signed, "ci@example", "https://token.actions.githubusercontent.com")[0] is False


def test_dashboard_orders_by_mtime_and_ignores_a_bad_score(tmp_path: Path) -> None:
    older = tmp_path / "zzz-old"
    newer = tmp_path / "aaa-new"
    junk = tmp_path / "junk"
    older.mkdir()
    newer.mkdir()
    junk.mkdir()
    (junk / "results.json").write_text("{", encoding="utf-8")
    (older / "results.json").write_text(
        json.dumps({"overall": "nope", "band": "fail", "results": [{"scenario_id": "old-fail", "passed": False}], "meta": {}}),
        encoding="utf-8",
    )
    time.sleep(0.05)
    (newer / "results.json").write_text(
        json.dumps(
            {
                "overall": 40,
                "band": "fail",
                "results": [{"scenario_id": "new-fail", "passed": False}],
                "meta": {"assessment": "assessed under A3P Method v1.0, level A3P-L0"},
            }
        ),
        encoding="utf-8",
    )
    rows = load_history(tmp_path)
    assert [row["name"] for row in rows] == ["zzz-old", "aaa-new"]
    assert rows[0]["overall"] == 0
    from a3p.dashboard import _score

    assert _score(True) == 1
    assert _score(1.5) == 1
    assert _score(None) == 0
    assert load_history(tmp_path / "missing") == []
    weird = tmp_path / "weird"
    weird.mkdir()
    (weird / "results.json").write_text("[]", encoding="utf-8")
    assert all(row["name"] != "weird" for row in load_history(tmp_path))
    page = render_history(rows)
    assert "aaa-new" in page
    assert "new-fail" in page
    assert "not a certification" in page.lower()


def test_dashboard_in_a_browser(tmp_path: Path) -> None:
    playwright_sync = pytest.importorskip("playwright.sync_api")
    older = tmp_path / "zzz-old"
    newer = tmp_path / "aaa-new"
    older.mkdir()
    newer.mkdir()
    (older / "results.json").write_text(
        json.dumps({"overall": 90, "band": "pass", "results": [{"scenario_id": "kept", "passed": True}], "meta": {}}),
        encoding="utf-8",
    )
    time.sleep(0.05)
    (newer / "results.json").write_text(
        json.dumps({"overall": 10, "band": "fail", "results": [{"scenario_id": "regressed", "passed": False}], "meta": {}}),
        encoding="utf-8",
    )
    server = serve(tmp_path, port=0)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    shot = tmp_path / "dashboard.png"
    try:
        with playwright_sync.sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1100, "height": 800})
            page.goto(f"http://127.0.0.1:{port}/", wait_until="domcontentloaded")
            page.get_by_role("heading", name="A3P run history").wait_for()
            body = page.inner_text("body")
            assert "zzz-old → aaa-new" in body
            assert "regressed" in body
            assert "not a certification" in body.lower()
            page.screenshot(path=str(shot), full_page=True)
            mobile = browser.new_page(viewport={"width": 390, "height": 780})
            mobile.goto(f"http://127.0.0.1:{port}/", wait_until="domcontentloaded")
            overflow = mobile.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
            missing = page.goto(f"http://127.0.0.1:{port}/missing", wait_until="commit")
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
    assert shot.stat().st_size > 1000
    assert overflow < 8
    assert missing is not None and missing.status == 404
    artifacts = Path(os.environ.get("A3P_ARTIFACTS_DIR", "artifacts"))
    try:
        if artifacts.is_dir():
            (artifacts / "dashboard-round10.png").write_bytes(shot.read_bytes())
    except OSError:
        pass


def _docker_or_skip() -> None:
    from a3p.isolation import _image_present, docker_prefix

    if docker_prefix() and _image_present(None):
        return
    if os.environ.get("A3P_REQUIRE_DOCKER") == "1":
        pytest.fail("Docker and the sandbox image were required and are not available")
    pytest.skip("Docker sandbox image is not available")


@pytest.mark.integration
def test_container_isolation_and_stdio_scan(tmp_path: Path) -> None:
    from a3p.isolation import attest

    _docker_or_skip()
    observed = attest("container")
    assert observed["level"] == "container"
    assert observed["network"] == "denied"
    assert observed["host_marker_intact"] is True
    report = run_live_scan(
        level="container",
        transport="stdio",
        output=tmp_path,
        probes=[{"id": "probe", "language": "en", "text": "note"}],
    )
    assert report["sandbox"] == "container"
    assert report["network"] == "denied"
    assert any(item["kind"] == "poisoning" for item in report["findings"])


@pytest.mark.integration
def test_container_sse_scan(tmp_path: Path) -> None:
    _docker_or_skip()
    report = run_live_scan(
        level="container",
        transport="sse",
        output=tmp_path,
        probes=[{"id": "probe", "language": "en", "text": "note"}],
    )
    assert report["transport"] == "sse"
    assert report["network"] == "denied"
    assert any(item["kind"] == "secret" for item in report["findings"])
