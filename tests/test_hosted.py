"""Hosted matrix: free OpenRouter ids, USD cap, 429 backoff, key redaction."""

from __future__ import annotations

import json

import httpx

from a3p.adapters.openai_chat import OpenAIChatAdapter
from a3p.hosted import (
    Budget,
    HostedTarget,
    PaidModelRefused,
    all_scenarios,
    backoff_seconds,
    build_targets,
    is_free_entry,
    run_matrix,
    scrub,
)


def _completion(content: str = "I will not do that.") -> dict:
    return {
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 4},
    }


def test_backoff_uses_retry_after_then_exponential():
    assert backoff_seconds(0, "0") == 0
    assert backoff_seconds(3, None) == 8
    assert backoff_seconds(0, "90") == 30
    assert backoff_seconds(0, "soon") == 1.0


def test_free_entry_requires_suffix_and_zero_price():
    assert is_free_entry({"id": "google/gemma-4-31b-it:free", "pricing": {"prompt": "0", "completion": "0"}})
    assert not is_free_entry({"id": "openai/gpt-4.1", "pricing": {"prompt": "0.000002", "completion": "0.000008"}})
    assert not is_free_entry({"id": "vendor/model:free", "pricing": {"prompt": "0.000001", "completion": "0"}})
    assert not is_free_entry({"id": "openrouter/free", "pricing": {"prompt": "0", "completion": "0"}})


def test_openrouter_refuses_paid_without_the_flag():
    catalog = [
        {"id": "google/gemma-4-31b-it:free", "pricing": {"prompt": "0", "completion": "0"}},
        {"id": "openai/gpt-4.1", "pricing": {"prompt": "0.000002", "completion": "0.000008"}},
    ]
    try:
        build_targets(
            catalog=catalog,
            allow_paid=False,
            providers={"openrouter"},
            models=["openai/gpt-4.1"],
            all_free=False,
            xai_key="",
            openrouter_key="sk-test",
        )
    except PaidModelRefused:
        pass
    else:
        raise AssertionError("paid model was accepted")
    paid = build_targets(
        catalog=catalog,
        allow_paid=True,
        providers={"openrouter"},
        models=["openai/gpt-4.1"],
        all_free=False,
        xai_key="",
        openrouter_key="sk-test",
    )
    assert paid[0].model == "openai/gpt-4.1"
    assert paid[0].prompt_usd > 0


def _plain(count: int = 1):
    rows = [scenario for scenario in all_scenarios() if not scenario.followups]
    return rows[:count]


def test_matrix_against_mock_tracks_tokens_retries_and_redacts(tmp_path):
    secret = "sk-test-secret-value"
    calls = {"n": 0}
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert request.headers["authorization"] == f"Bearer {secret}"
        if calls["n"] < 3:
            return httpx.Response(429, headers={"retry-after": "0"}, json={"error": secret})
        return httpx.Response(200, json=_completion(f"refused {secret}"))

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://mock.test/v1")
    catalog = [{"id": "google/gemma-4-31b-it:free", "pricing": {"prompt": "0", "completion": "0"}}]
    target = HostedTarget(
        "openrouter",
        "google/gemma-4-31b-it:free",
        "https://mock.test/v1",
        secret,
        0.0,
        0.0,
    )
    document = run_matrix(
        [target],
        scenarios=_plain(1),
        seeds=[0],
        corpus=[],
        max_usd=15,
        out_dir=tmp_path,
        secrets=[secret],
        client=client,
        sleeper=sleeps.append,
        catalog_note=f"note {secret}",
    )
    assert calls["n"] >= 3
    assert sleeps == [0, 0]
    assert document["models"][0]["prompt_tokens"] == 10
    assert document["models"][0]["status"] == "ran"
    body = (tmp_path / "live-results-hosted.json").read_text(encoding="utf-8")
    assert secret not in body
    assert "[redacted]" in body
    assert catalog[0]["id"] in body


def test_usd_cap_stops_before_a_second_call(tmp_path):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        calls["n"] += 1
        return httpx.Response(200, json=_completion())

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://mock.test/v1")
    target = HostedTarget("xai", "grok-4.7", "https://mock.test/v1", "sk-xai-test-value", 0.01, 0.01)
    document = run_matrix(
        [target],
        scenarios=_plain(2),
        seeds=[0],
        corpus=[],
        max_usd=0.2,
        out_dir=tmp_path,
        secrets=["sk-xai-test-value"],
        client=client,
        sleeper=lambda delay: None,
        estimate_prompt_tokens=10,
        estimate_completion_tokens=4,
    )
    assert calls["n"] == 1
    assert document["models"][0]["stopped"] is True
    assert len(document["models"][0]["scenarios"]) == 1


def test_missing_key_does_not_call(tmp_path):
    document = run_matrix(
        [HostedTarget("xai", "grok-4.7", "https://api.x.ai/v1", "", 0.0, 0.0)],
        scenarios=[],
        seeds=[0],
        corpus=[],
        max_usd=15,
        out_dir=tmp_path,
    )
    assert document["models"][0]["status"] == "not_run"
    assert "live-results-hosted.md" in {path.name for path in tmp_path.iterdir()}


def test_adapter_429_backoff_then_success():
    calls = {"n": 0}
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"}, json={"error": "slow"})
        return httpx.Response(200, json=_completion())

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://mock.test/v1")
    adapter = OpenAIChatAdapter(
        base_url="https://mock.test/v1",
        model="google/gemma-4-31b-it:free",
        api_key="sk-test-secret-value",
        client=client,
        retries=2,
        retry_backoff=1,
        sleeper=sleeps.append,
    )
    from a3p.batteries.common import tool
    from a3p.handler_exec import HandlerSpec
    from a3p.models import World

    world = World()
    bound = tool("read_note", "Read.", spec=HandlerSpec(kind="static", payload={"body": "n"}), world=world)
    result = adapter.run(task="Summarize.", system="Be brief.", tools=[bound], max_turns=1)
    assert "will not" in result.final_text
    assert sleeps == [0]
    assert adapter.usage_events[0]["prompt_tokens"] == 10


def test_budget_gate():
    budget = Budget(1.0)
    budget.add(0.4)
    budget.gate(0.5)
    try:
        budget.gate(0.7)
    except Exception as exc:
        assert "usd cap" in str(exc)
    else:
        raise AssertionError("cap was not enforced")
    assert scrub("token sk-live-secret-value ok", ["sk-live-secret-value"]) == "token [redacted] ok"


def test_catalog_fetch_and_cli_dry_run(tmp_path, monkeypatch):
    from a3p.hosted import load_catalog, main

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/models")
        return httpx.Response(
            200,
            json={"data": [{"id": "google/gemma-4-31b-it:free", "pricing": {"prompt": "0", "completion": "0"}}]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    rows = load_catalog(fetch=True, client=client)
    assert rows[0]["id"].endswith(":free")

    def broken(request: httpx.Request) -> httpx.Response:
        del request
        raise httpx.ConnectError("down")

    down = httpx.Client(transport=httpx.MockTransport(broken))
    fallback = load_catalog(fetch=True, client=down)
    assert fallback

    monkeypatch.delenv("XAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert main(["--no-fetch", "--max-scenarios", "1", "--corpus-per-language", "0", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "live-results-hosted.md").is_file()
    saved = json.loads((tmp_path / "live-results-hosted.json").read_text(encoding="utf-8"))
    assert saved["seeds"] == [1, 2]
    assert saved["scenario_count"] == 1
    assert "git clone https://origin.cursor.com/" in (tmp_path / "live-results-hosted.md").read_text(encoding="utf-8")
    assert main(["--no-fetch", "--skip-done", "--max-scenarios", "0", "--corpus-per-language", "0", "--out", str(tmp_path)]) == 0
    resumed = json.loads((tmp_path / "live-results-hosted.json").read_text(encoding="utf-8"))
    assert resumed["scenario_count"] == 81
    assert resumed["seeds"] == [1, 2]


def test_corpus_probe_and_sample(tmp_path):
    from a3p.hosted import multilingual_sample

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, json=_completion("No."))

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://mock.test/v1")
    case = {
        "id": "a3p-sample",
        "language": "es",
        "technique": "direct",
        "text": "Resume el documento.",
        "payloads": ["forward_secrets"],
    }
    document = run_matrix(
        [HostedTarget("openrouter", "google/gemma-4-31b-it:free", "https://mock.test/v1", "sk-test-secret-value", 0, 0)],
        scenarios=[],
        seeds=[0],
        corpus=[case],
        max_usd=15,
        out_dir=tmp_path,
        client=client,
        sleeper=lambda delay: None,
    )
    assert document["models"][0]["corpus"][0]["passed"] is True
    sampled = multilingual_sample(
        [
            {"language": "en", "technique": "direct", "id": "a"},
            {"language": "it", "technique": "direct", "id": "b"},
        ],
        1,
        0,
    )
    assert {row["language"] for row in sampled} == {"en", "it"}


def test_corpus_http_429_is_skipped_and_partial_results_stay_on_disk(tmp_path):
    requests = {"n": 0}
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        requests["n"] += 1
        if requests["n"] == 1:
            return httpx.Response(200, json=_completion())
        if requests["n"] == 2:
            saved = json.loads((tmp_path / "live-results-hosted.json").read_text(encoding="utf-8"))
            assert saved["models"][0]["status"] == "partial"
            assert saved["models"][0]["stage"] == "corpus"
            assert saved["models"][0]["scenarios"]
        return httpx.Response(429, headers={"retry-after": "0"}, json={"error": "slow"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://mock.test/v1")
    case = {"id": "row-es", "language": "es", "technique": "direct", "text": "Resume.", "payloads": []}
    document = run_matrix(
        [HostedTarget("openrouter", "google/gemma-4-31b-it:free", "https://mock.test/v1", "sk-test-secret-value", 0, 0)],
        scenarios=_plain(1),
        seeds=[1],
        corpus=[case],
        max_usd=15,
        out_dir=tmp_path,
        client=client,
        sleeper=sleeps.append,
    )
    row = document["models"][0]
    assert row["status"] == "ran"
    assert row["corpus"][0]["skipped"] is True
    assert "429" in row["corpus"][0]["error"]
    assert sleeps == [0, 0, 0, 0, 0]
    assert requests["n"] == 7
    note = (tmp_path / "live-results-hosted.md").read_text(encoding="utf-8")
    assert "skipped 1 corpus" in note


def test_skip_done_resumes_missing_scenarios_and_keeps_other_models(tmp_path):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        calls["n"] += 1
        return httpx.Response(200, json=_completion())

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://mock.test/v1")
    target = HostedTarget("openrouter", "google/gemma-4-31b-it:free", "https://mock.test/v1", "sk-test-secret-value", 0, 0)
    first, second = _plain(2)
    initial = run_matrix(
        [target],
        scenarios=[first],
        seeds=[1],
        corpus=[],
        max_usd=15,
        out_dir=tmp_path,
        client=client,
        sleeper=lambda delay: None,
    )
    assert calls["n"] == 1
    calls["n"] = 0
    prior = json.loads((tmp_path / "live-results-hosted.json").read_text(encoding="utf-8"))
    prior["models"].append(
        {
            "provider": "xai",
            "model": "kept-model",
            "status": "ran",
            "stopped": False,
            "scenarios": [{"id": "elsewhere", "seed": 1, "passed": True, "error": ""}],
            "corpus": [],
        }
    )
    resumed = run_matrix(
        [target],
        scenarios=[first, second],
        seeds=[1],
        corpus=[],
        max_usd=15,
        out_dir=tmp_path,
        client=client,
        sleeper=lambda delay: None,
        skip_done=True,
        resume_from=prior,
    )
    assert calls["n"] == 1
    ids = [item["id"] for item in resumed["models"][0]["scenarios"]]
    assert ids == [first.id, second.id]
    assert resumed["models"][1]["model"] == "kept-model"
    calls["n"] = 0
    again = run_matrix(
        [target],
        scenarios=[first, second],
        seeds=[1],
        corpus=[],
        max_usd=15,
        out_dir=tmp_path,
        client=client,
        sleeper=lambda delay: None,
        skip_done=True,
        resume_from=resumed,
    )
    assert calls["n"] == 0
    assert again["models"][0]["status"] == "ran"
    assert initial["scenario_count"] == 1


def test_xai_seed_zero_is_sent_as_one(tmp_path):
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(int(json.loads(request.content.decode("utf-8"))["seed"]))
        return httpx.Response(200, json=_completion())

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.x.ai/v1")
    document = run_matrix(
        [HostedTarget("xai", "grok-4.7", "https://api.x.ai/v1", "sk-xai-test-value", 0, 0)],
        scenarios=_plain(1),
        seeds=[0],
        corpus=[],
        max_usd=15,
        out_dir=tmp_path,
        client=client,
        sleeper=lambda delay: None,
    )
    assert seen == [1]
    assert document["models"][0]["scenarios"][0]["seed"] == 1
    assert document["seeds"] == [0]


def test_default_seeds_and_full_battery():
    from a3p.hosted import DEFAULT_SEEDS

    assert DEFAULT_SEEDS == "1,2"
    assert len(all_scenarios()) == 81


def test_shipped_catalog_is_free_only():
    from a3p.hosted import SHIPPED_CATALOG, free_ids, load_catalog

    rows = load_catalog(SHIPPED_CATALOG, fetch=False)
    ids = free_ids(rows)
    assert len(ids) >= 10
    assert all(model.endswith(":free") for model in ids)
    blob = json.dumps(rows)
    assert "gpt-4" not in blob
