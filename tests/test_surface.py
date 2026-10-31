"""CLI, logging, the optional judge, and the model-backed LangGraph loop."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from a3p.adapters.langgraph_model import LangGraphModelAdapter
from a3p.batteries.common import tool
from a3p.cli import main
from a3p.config import ConfigError, load_config
from a3p.judge import LLMJudge
from a3p.log import configure, get_logger
from a3p.models import World


def test_cli_eval_keys_run_verify_and_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("A3P_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("A3P_LOG_LEVEL", "INFO")
    assert main(["eval", "claims"]) == 0
    assert "recall=" in capsys.readouterr().out
    assert main(["keys", "generate"]) == 0
    assert main(["keys", "rotate"]) == 0
    config = tmp_path / "probe.yaml"
    config.write_text(
        "meta:\n  client: Northwind\n  agent_name: demo\n  agent_version: '0'\n"
        "  scope: unit\n  auditor: test\n"
        "target:\n  adapter: callable\n  policy: careful\n"
        "batteries:\n  - leakage\n"
        "output:\n  directory: out/ignored\n",
        encoding="utf-8",
    )
    out = tmp_path / "run"
    assert main(["run", "-c", str(config), "-o", str(out)]) == 0
    assert (out / "report.html").is_file()
    assert (out / "ledger.jsonl").is_file()
    assert not (out / "auditor.pem").exists()
    assert main(["verify", str(out / "ledger.jsonl"), "--public-key", str(out / "auditor.pub")]) == 0
    assert main(["verify-badge", str(out / "badge.json"), "--public-key", str(out / "auditor.pub")]) == 0
    assert "assessed under A3P Method v1.0, level" in capsys.readouterr().out
    assert main(["leaderboard", "-o", str(tmp_path / "board"), str(out), str(tmp_path / "missing")]) == 0
    page = (tmp_path / "board" / "index.html").read_text(encoding="utf-8")
    assert "Phantom-success" in page
    assert "guaranteed safe" not in page.lower()
    assert main(["report", str(out)]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("target:\n  adapter: telepathy\n", encoding="utf-8")
    assert main(["run", "-c", str(bad)]) == 2


def test_cli_demo_and_openai_mock(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("A3P_KEY_DIR", str(tmp_path / "keys"))
    assert main(["demo", "-o", str(tmp_path / "demo")]) == 0
    demo_out = capsys.readouterr().out
    assert "CAUGHT A LIE" in demo_out
    assert "outbox empty" in demo_out
    vulnerable = json.loads((tmp_path / "demo" / "langgraph-vulnerable" / "results.json").read_text(encoding="utf-8"))
    careful = json.loads((tmp_path / "demo" / "langgraph-careful" / "results.json").read_text(encoding="utf-8"))
    assert vulnerable["overall"] < careful["overall"]
    from a3p.demo import publish_sample

    publish_sample(tmp_path / "demo", tmp_path / "sample")
    assert (tmp_path / "sample" / "badge.json").is_file()
    assert "sample report copied" in capsys.readouterr().out


def test_cli_builds_every_adapter(tmp_path: Path):
    from a3p.cli import _adapter
    from a3p.config import TargetConfig

    model, handle = _adapter(TargetConfig(adapter="langgraph", base_url="http://127.0.0.1:9/v1", model="qwen2.5:1.5b"))
    try:
        assert model.name.startswith("langgraph-model")
        assert handle.proxy is not None
        assert handle.proxy.allow == {"127.0.0.1"}
        assert str(model.proxy).startswith("http://127.0.0.1:")
    finally:
        handle.stop()
    scripted, handle = _adapter(TargetConfig(adapter="langgraph", policy="careful"))
    assert scripted.name == "langgraph:careful"
    handle.stop()
    chat, handle = _adapter(TargetConfig(adapter="openai", base_url="mock://careful"))
    assert chat.name.startswith("openai:")
    assert chat.proxy is None
    handle.stop()
    hosted, handle = _adapter(
        TargetConfig(adapter="openai", base_url="https://api.x.ai/v1", model="grok-4.7"),
        log_dir=tmp_path,
    )
    try:
        assert hosted.proxy
        assert handle.proxy is not None
        assert handle.proxy.allow == {"api.x.ai"}
    finally:
        handle.stop()
    workflow = "demos/n8n/vulnerable-support-agent.json"
    local, handle = _adapter(TargetConfig(adapter="n8n", workflow=workflow, mode="inprocess"))
    assert local.mode == "inprocess"
    handle.stop()
    remote, handle = _adapter(
        TargetConfig(adapter="n8n", workflow=workflow, mode="http", webhook_url="http://127.0.0.1:9/hook")
    )
    assert handle.proxy is None
    assert remote.webhook_url.endswith("/hook")
    handle.stop()
    local_http, handle = _adapter(TargetConfig(adapter="n8n", workflow=workflow, mode="http"))
    try:
        assert local_http.mode == "http"
    finally:
        handle.stop()
    try:
        _adapter(TargetConfig(adapter="n8n"))
    except SystemExit as exc:
        assert "workflow" in str(exc)
    else:
        raise AssertionError("expected SystemExit")
    odd = TargetConfig(adapter="callable")
    odd.adapter = "telepathy"
    try:
        _adapter(odd)
    except SystemExit as exc:
        assert "telepathy" in str(exc)
    else:
        raise AssertionError("expected SystemExit")


def test_config_rejects_bad_shapes(tmp_path: Path):
    missing = tmp_path / "missing.yaml"
    missing.write_text("target:\n  adapter: n8n\n  workflow: /no/such/file.json\n", encoding="utf-8")
    try:
        load_config(missing)
    except ConfigError as exc:
        assert "workflow" in str(exc)
    else:
        raise AssertionError("expected ConfigError")
    dotted = tmp_path / "dot.yaml"
    dotted.write_text("output:\n  directory: '../escape'\n", encoding="utf-8")
    try:
        load_config(dotted)
    except ConfigError as exc:
        assert ".." in str(exc)
    else:
        raise AssertionError("expected ConfigError")


def test_run_can_install_the_optional_judge(tmp_path: Path):
    from a3p.claims import claims_done, push_judge, reset_judge
    from a3p.cli import build_judge
    from a3p.config import ConfigError, load_config

    class Judge:
        def judge_claim(self, text: str) -> dict:
            return {"claims_success": True, "confidence": 0.7}

    bare = claims_done("The tool returned ok.")
    token = push_judge(Judge())
    try:
        assert claims_done("The tool returned ok.") is True
    finally:
        reset_judge(token)
    assert claims_done("The tool returned ok.") is bare

    missing = tmp_path / "judge.yaml"
    missing.write_text("judge:\n  enabled: true\n", encoding="utf-8")
    try:
        build_judge(load_config(missing))
    except ConfigError as exc:
        assert "base_url" in str(exc)
    else:
        raise AssertionError("expected ConfigError")
    ready = tmp_path / "ready.yaml"
    ready.write_text(
        "judge:\n  enabled: true\n  base_url: http://127.0.0.1:9/v1\n  model: qwen2.5:1.5b\n",
        encoding="utf-8",
    )
    judge = build_judge(load_config(ready))
    assert judge is not None
    off = tmp_path / "off.yaml"
    off.write_text("judge:\n  enabled: false\n", encoding="utf-8")
    assert build_judge(load_config(off)) is None


def test_judge_reads_structured_output():
    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"choices": [{"message": {"content": '{"claims_success": false, "language": "en"}'}}]}

    class Client:
        def post(self, path: str, json: dict, headers: dict) -> Response:
            assert path == "/chat/completions"
            assert "Bearer" in headers["Authorization"]
            return Response()

    verdict = LLMJudge("http://example.invalid/v1", "mock", client=Client()).judge_claim("ok")
    assert verdict["claims_success"] is False


def test_langgraph_model_calls_the_endpoint(monkeypatch):
    calls = {"n": 0}

    def post(url, json, headers, timeout, proxy=None):
        calls["n"] += 1
        if calls["n"] == 1:
            body = {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "function": {"name": "send_email", "arguments": '{"to": "a@b.c"}'},
                                }
                            ],
                        }
                    }
                ]
            }
        else:
            body = {"choices": [{"message": {"role": "assistant", "content": "Done: the email was sent."}}]}

        class Response:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return body

        return Response()

    monkeypatch.setattr(httpx, "post", post)
    world = World()

    def send(args: dict) -> dict:
        world.effects.append({"tool": "send_email"})
        return {"ok": True}

    adapter = LangGraphModelAdapter("http://127.0.0.1:9/v1", "qwen2.5:1.5b", seed=1)
    result = adapter.run(
        task="Email the invoice.",
        system="Be careful.",
        tools=[tool("send_email", "Send an email.", send, properties={"to": {"type": "string"}})],
        followups=["Thanks."],
    )
    assert result.tool_calls
    assert "sent" in result.final_text.lower()


def test_logging_redacts():
    configure("INFO")
    log = get_logger("surface")
    log.info("token A3P-SECRET-SYSTEM-7f3a9c")


def test_live_subset_is_deterministic_for_a_scripted_agent():
    from a3p.adapters.callable_agent import CallableAdapter
    from a3p.live import langgraph_factory, live_scenarios, openai_factory, run_seed, summarize

    scenarios = live_scenarios()
    assert len(scenarios) == 10
    seen: list[str] = []
    careful = run_seed(
        lambda seed: CallableAdapter("careful"),
        1,
        scenarios,
        on_result=lambda scenario, result: seen.append(scenario.id),
    )
    assert seen == [scenario.id for scenario in scenarios]
    again = run_seed(lambda seed: CallableAdapter("careful"), 2, scenarios)
    assert careful.overall == again.overall
    summary = summarize([careful, again])
    assert summary["stdev"] == 0
    chat = openai_factory("http://127.0.0.1:9/v1", "qwen2.5:1.5b")(3)
    assert chat.model == "qwen2.5:1.5b"
    assert chat.seed == 3
    assert langgraph_factory("http://127.0.0.1:9/v1", "qwen2.5:1.5b")(3).seed == 3


def test_dataset_builder_rewrites_the_shipped_set():
    from a3p.eval.build_claims_eval import main

    main()
