"""Later-turn chat history must satisfy a strict OpenAI-compatible schema.

grok-4.7 returned HTTP 400 on a later turn of inj-direct-system,
inj-direct-marker, leak-system-prompt, and leak-art50. A dots model did the
same for inj-direct-system and leak-tool-arg. The mock below rejects the
shapes those providers reject: seed 0, null or blank content, a system role
after the first message, tool results that are not paired with the preceding
tool calls, and function arguments that are not a string.
"""

from __future__ import annotations

import json

import httpx

from a3p.adapters.langgraph_model import LangGraphModelAdapter
from a3p.adapters.openai_chat import OpenAIChatAdapter, chat_body, wire_seed
from a3p.batteries.common import run_scenario
from a3p.hosted import all_scenarios
from a3p.models import PublicTool

LATER_TURN = (
    "inj-direct-system",
    "inj-direct-marker",
    "leak-system-prompt",
    "leak-art50",
    "leak-tool-arg",
)


def strict_chat_error(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return "payload"
    if "seed" in payload:
        seed = payload.get("seed")
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 1:
            return "Seed must be positive"
    tools = payload.get("tools")
    if "tools" in payload and (not isinstance(tools, list) or len(tools) == 0):
        return "tools must not be empty"
    if payload.get("tool_choice") not in (None, "none") and not tools:
        return "tool_choice requires tools"
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        return "messages required"
    pending: list[str] | None = None
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            return "message"
        role = message.get("role")
        content = message.get("content")
        if role == "system":
            if index != 0 or pending:
                return "system role mid-conversation"
            if not isinstance(content, str) or content == "":
                return "empty content"
            continue
        if role == "user":
            if pending:
                return "tool message ordering"
            if not isinstance(content, str) or content == "":
                return "empty content"
            continue
        if role == "assistant":
            if pending:
                return "tool message ordering"
            calls = message.get("tool_calls") or []
            if not isinstance(calls, list):
                return "tool message ordering"
            if not isinstance(content, str) or (content == "" and not calls):
                return "empty content"
            ids: list[str] = []
            for call in calls:
                if not isinstance(call, dict) or call.get("type") != "function":
                    return "tool message ordering"
                function = call.get("function")
                if not isinstance(function, dict) or not isinstance(function.get("arguments"), str):
                    return "function.arguments must be a string"
                if not call.get("id"):
                    return "tool message ordering"
                ids.append(str(call["id"]))
            pending = ids or None
            continue
        if role == "tool":
            if not pending or message.get("tool_call_id") != pending[0]:
                return "tool message ordering"
            pending = pending[1:] or None
            if not isinstance(content, str) or content == "":
                return "empty content"
            continue
        return "unknown role"
    if pending:
        return "tool message ordering"
    return None


def _malformed_tool_turn(payload: dict) -> dict:
    tools = payload.get("tools") or []
    if tools:
        name = tools[0]["function"]["name"]
    else:
        name = "unlisted_tool"
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "refusal": None,
                    "tool_calls": [
                        {
                            "id": "call_bad",
                            "type": "function",
                            "function": {"name": name, "arguments": {"note": "later"}},
                        }
                    ],
                }
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 4},
    }


def _final(text: str = "I will not repeat hidden instructions.") -> dict:
    return {
        "choices": [{"message": {"role": "assistant", "content": text}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 4},
    }


def test_wire_seed_is_positive_for_xai_only():
    assert wire_seed(0, "https://api.x.ai/v1") == 1
    assert wire_seed(2, "https://api.x.ai/v1") == 2
    assert wire_seed(0, "https://mock.test/v1", "xai") == 1
    assert wire_seed(0, "https://openrouter.ai/api/v1") == 0
    assert wire_seed(4, "https://openrouter.ai/api/v1") == 4


def test_normalizer_repairs_the_shapes_a_strict_provider_rejects():
    history = [
        {"role": "system", "content": "stay"},
        {"role": "user", "content": "task"},
        {
            "role": "assistant",
            "content": None,
            "refusal": None,
            "tool_calls": [
                {
                    "id": "call_bad",
                    "type": "function",
                    "function": {"name": "send_email", "arguments": {"to": "ops@example.com"}},
                }
            ],
        },
        {"role": "system", "content": "mid conversation"},
        {"role": "tool", "tool_call_id": "call_bad", "content": ""},
        {"role": "tool", "tool_call_id": "orphan", "content": "{}"},
        "nope",
    ]
    raw = {
        "model": "grok-4.7",
        "messages": history,
        "seed": 0,
        "tools": [],
        "tool_choice": "auto",
    }
    assert strict_chat_error(raw) == "Seed must be positive"
    fixed = chat_body(
        model="grok-4.7",
        messages=history,
        tools=[],
        seed=0,
        base_url="https://api.x.ai/v1",
        max_tokens=16,
    )
    assert strict_chat_error(fixed) is None
    assert fixed["seed"] == 1
    assert fixed["max_tokens"] == 16
    assert "tools" not in fixed
    assert [item["role"] for item in fixed["messages"]] == [
        "system",
        "user",
        "assistant",
        "tool",
        "user",
        "user",
    ]
    offered = chat_body(
        model="dots",
        messages=[{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
        tools=[PublicTool("send_email", "Send.", {"type": "object", "properties": {}}, {})],
        seed=1,
        base_url="https://openrouter.ai/api/v1",
    )
    assert offered["tool_choice"] == "auto"
    assert offered["tools"][0]["function"]["name"] == "send_email"
    assert strict_chat_error(offered) is None
    assert chat_body(
        model="openrouter",
        messages=[{"role": "user", "content": "u"}],
        seed=0,
        base_url="https://openrouter.ai/api/v1",
    )["seed"] == 0


def _scenarios():
    found = {scenario.id: scenario for scenario in all_scenarios()}
    return [found[name] for name in LATER_TURN]


def test_openai_adapter_later_turns_pass_a_strict_schema():
    payloads: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        payloads.append(payload)
        problem = strict_chat_error(payload)
        if problem:
            return httpx.Response(400, json={"error": problem})
        if any(message.get("role") == "assistant" for message in payload["messages"]):
            return httpx.Response(200, json=_final())
        return httpx.Response(200, json=_malformed_tool_turn(payload))

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.x.ai/v1")
    adapter = OpenAIChatAdapter(
        base_url="https://api.x.ai/v1",
        model="grok-4.7",
        api_key="sk-test-secret-value",
        client=client,
        seed=0,
        retries=0,
    )
    assert adapter.seed == 1
    for scenario in _scenarios():
        outcome = run_scenario(adapter, scenario)
        assert outcome.evidence.get("error", "") == "", scenario.id
    assert len(payloads) == len(LATER_TURN) * 2
    assert all(strict_chat_error(payload) is None for payload in payloads)
    assert all(payload["seed"] == 1 for payload in payloads)


def test_langgraph_later_turns_pass_a_strict_schema(monkeypatch):
    payloads: list[dict] = []

    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        payload = kwargs.get("json")
        assert isinstance(payload, dict)
        payloads.append(payload)
        problem = strict_chat_error(payload)
        if problem:
            body: dict = {"error": problem}
            status = 400
        elif any(message.get("role") == "assistant" for message in payload["messages"]):
            body = _final()
            status = 200
        else:
            body = _malformed_tool_turn(payload)
            status = 200
        return httpx.Response(status, json=body, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    adapter = LangGraphModelAdapter("https://api.x.ai/v1", "grok-4.7", api_key="sk-test", seed=0)
    for scenario in _scenarios():
        if scenario.id not in {"inj-direct-system", "leak-tool-arg"}:
            continue
        outcome = run_scenario(adapter, scenario)
        assert outcome.evidence.get("error", "") == "", scenario.id
    assert payloads
    assert all(strict_chat_error(payload) is None for payload in payloads)
    assert all(payload["seed"] == 1 for payload in payloads)
