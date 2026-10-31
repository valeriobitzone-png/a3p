"""OpenAI-compatible chat adapter with tools.

`base_url` may be an http(s) endpoint (`.../v1`) or `mock://vulnerable` /
`mock://careful`, which never leaves the process. Tests can also pass an
httpx.Client so the HTTP parsing path runs against a local server.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import httpx

from a3p.models import AgentResult, BoundTool, PublicTool, ToolCall
from a3p.policy import StepCall, StepFinal, step


def _schema(tool: PublicTool) -> dict:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters or {"type": "object", "properties": {}},
        },
    }


def scripted_completion(
    messages: list[dict],
    tools: list[PublicTool],
    *,
    cautious: bool,
) -> dict:
    """Stand-in model. Speaks the chat-completions tool-call shape."""
    system = ""
    task = ""
    observations: list[ToolCall] = []
    pending: dict[str, dict] = {}
    for message in messages:
        role = message.get("role")
        if role == "system":
            system = message.get("content") or ""
        elif role == "user":
            task = message.get("content") or ""
        elif role == "assistant":
            for call in message.get("tool_calls") or []:
                fn = call.get("function") or {}
                raw = fn.get("arguments") or "{}"
                try:
                    args = json.loads(raw) if isinstance(raw, str) else raw
                except json.JSONDecodeError:
                    args = {}
                key = str(call.get("id") or fn.get("name") or "")
                pending[key] = {
                    "name": fn.get("name"),
                    "arguments": args,
                }
        elif role == "tool":
            call_id = str(message.get("tool_call_id") or "")
            meta = pending.pop(call_id, None)
            if meta is None:
                continue
            try:
                result = json.loads(message.get("content") or "null")
            except json.JSONDecodeError:
                result = message.get("content")
            observations.append(ToolCall(meta["name"], meta["arguments"], result))
    decision = step(task, system, tools, observations, cautious=cautious)
    if isinstance(decision, StepFinal):
        return _message(content=decision.text)
    assert isinstance(decision, StepCall)
    call_id = f"call_{len(observations) + 1}"
    return _message(
        tool_calls=[
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": decision.name,
                    "arguments": json.dumps(decision.arguments, default=str),
                },
            }
        ]
    )


def _message(*, content: str | None = None, tool_calls: list | None = None) -> dict:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
        message["content"] = None
    return {
        "id": "chatcmpl-a3p",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": message, "finish_reason": "stop" if not tool_calls else "tool_calls"}],
    }


def wire_seed(seed: int, base_url: str = "", provider: str = "") -> int:
    """Seed value safe to put on the wire.

    xAI rejects ``seed=0`` ("Seed must be positive"). Other providers keep the
    requested seed, including 0. The hosted matrix defaults to 1 and 2 so every
    provider in that run uses the same positive pair.
    """
    host = ""
    try:
        host = httpx.URL(base_url).host.lower()
    except Exception:
        host = ""
    positive = provider == "xai" or host == "api.x.ai" or host.endswith(".x.ai")
    if positive and seed < 1:
        return 1
    return seed


def _text(value: object) -> str:
    if isinstance(value, str):
        text = value
    elif value is None:
        text = ""
    else:
        text = json.dumps(value, default=str)
    return text if text.strip() else " "


def normalize_tool_call(call: object, index: int) -> dict[str, Any]:
    raw_call: dict[str, Any] = call if isinstance(call, dict) else {}
    function_raw = raw_call.get("function")
    function: dict[str, Any] = function_raw if isinstance(function_raw, dict) else {}
    name = str(function.get("name") or raw_call.get("name") or "tool")
    arguments = function.get("arguments")
    if arguments is None:
        arguments = raw_call.get("arguments")
    if isinstance(arguments, str):
        encoded = arguments.strip() or "{}"
    else:
        encoded = json.dumps(arguments if isinstance(arguments, dict) else {}, default=str)
    return {
        "id": str(raw_call.get("id") or f"call_{index + 1}"),
        "type": "function",
        "function": {"name": name, "arguments": encoded},
    }


def replay_message(message: dict) -> dict[str, Any]:
    """Assistant message safe to send back: string content, string arguments."""
    calls = [normalize_tool_call(call, index) for index, call in enumerate(message.get("tool_calls") or [])]
    body: dict[str, Any] = {"role": "assistant", "content": _text(message.get("content"))}
    if calls:
        body["tool_calls"] = calls
    return body


def tool_result_message(call_id: str, result: object) -> dict[str, str]:
    if isinstance(result, str) and result.strip():
        content = result
    else:
        content = json.dumps({} if result is None or result == "" else result, default=str)
        if not content.strip() or content == "null":
            content = "{}"
    return {"role": "tool", "tool_call_id": call_id, "content": content}


def normalize_messages(messages: list[dict]) -> list[dict]:
    """One leading system message, then user, assistant, and paired tool results.

    A later ``system`` role becomes a user turn. Tool results are emitted in
    tool-call order and only for ids the preceding assistant message declared.
    """
    output: list[dict] = []
    index = 0
    while index < len(messages):
        message = messages[index] if isinstance(messages[index], dict) else {}
        role = message.get("role")
        if role == "system":
            text = _text(message.get("content"))
            output.append({"role": "system" if not output else "user", "content": text})
            index += 1
            continue
        if role == "assistant":
            replayed = replay_message(message)
            calls = list(replayed.get("tool_calls") or [])
            output.append(replayed)
            index += 1
            if not calls:
                continue
            pending: list[dict] = []
            deferred: list[dict] = []
            while index < len(messages):
                nxt = messages[index] if isinstance(messages[index], dict) else {}
                nxt_role = nxt.get("role")
                if nxt_role == "tool":
                    pending.append(nxt)
                    index += 1
                    continue
                if nxt_role == "system":
                    deferred.append(nxt)
                    index += 1
                    continue
                break
            by_id: dict[str, dict] = {}
            for item in pending:
                by_id.setdefault(str(item.get("tool_call_id") or ""), item)
            for call in calls:
                match = by_id.get(str(call["id"]))
                if match is None:
                    continue
                raw = match.get("content")
                output.append(tool_result_message(str(call["id"]), "{}" if raw in (None, "") else raw))
            for item in deferred:
                output.append({"role": "user", "content": _text(item.get("content"))})
            continue
        if role == "tool":
            index += 1
            continue
        output.append({"role": "user", "content": _text(message.get("content"))})
        index += 1
    return output


def chat_body(
    *,
    model: str,
    messages: list[dict],
    tools: list[PublicTool] | None = None,
    schemas: list[dict] | None = None,
    seed: int | None = None,
    base_url: str = "",
    provider: str = "",
    max_tokens: int | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": model,
        "messages": normalize_messages(messages),
        "temperature": 0,
    }
    if seed is not None:
        body["seed"] = wire_seed(seed, base_url, provider)
    encoded = list(schemas) if schemas is not None else [_schema(tool) for tool in (tools or [])]
    if encoded:
        body["tools"] = encoded
        body["tool_choice"] = "auto"
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    return body


class OpenAIChatAdapter:
    def __init__(
        self,
        base_url: str = "mock://vulnerable",
        model: str = "a3p-mock",
        api_key: str = "mock",
        *,
        client: httpx.Client | None = None,
        proxy: str | None = None,
        timeout: float = 30.0,
        retries: int = 2,
        seed: int = 1,
        provider: str = "",
        max_tokens: int | None = None,
        on_usage: Callable[[dict], None] | None = None,
        before_request: Callable[[], None] | None = None,
        retry_backoff: float = 0.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self._client = client
        self.proxy = proxy
        self.timeout = timeout
        self.retries = retries
        self.provider = provider
        self.seed = wire_seed(seed, self.base_url, provider)
        self.max_tokens = max_tokens
        self.on_usage = on_usage
        self.before_request = before_request
        self.retry_backoff = retry_backoff
        self.sleeper = sleeper or time.sleep
        self.usage_events: list[dict] = []
        self.name = f"openai:{self.base_url}"

    def run(
        self,
        *,
        task: str,
        system: str,
        tools: list[BoundTool],
        max_turns: int = 6,
        followups: list[str] | None = None,
    ) -> AgentResult:
        from a3p.sandbox import invoke_tool

        public = [tool.public for tool in tools]
        handlers = {tool.public.name: tool.handler for tool in tools}
        messages: list[dict] = [
            {"role": "system", "content": system},
            {"role": "user", "content": task},
        ]
        pending = list(followups or [])
        calls: list[ToolCall] = []
        turns = max_turns + len(pending)
        for _ in range(turns):
            completion = self._complete(messages, public)
            message = completion["choices"][0]["message"]
            tool_calls = [normalize_tool_call(call, index) for index, call in enumerate(message.get("tool_calls") or [])]
            if not tool_calls:
                if pending:
                    messages.append(replay_message({"content": message.get("content") or " "}))
                    messages.append({"role": "user", "content": _text(pending.pop(0))})
                    continue
                return AgentResult(message.get("content") or "", calls)
            messages.append(replay_message({"content": message.get("content"), "tool_calls": tool_calls}))
            for call in tool_calls:
                fn = call["function"]
                raw = fn.get("arguments") or "{}"
                try:
                    arguments = json.loads(raw) if isinstance(raw, str) else dict(raw)
                except json.JSONDecodeError:
                    arguments = {}
                handler = handlers.get(fn["name"])
                result = invoke_tool(handler, arguments) if handler else {"error": f"unknown tool {fn['name']}"}
                calls.append(ToolCall(fn["name"], arguments, result))
                messages.append(tool_result_message(str(call.get("id") or fn["name"]), result))
        return AgentResult("Stopped: tool-turn limit reached before a final answer.", calls)

    def _complete(self, messages: list[dict], tools: list[PublicTool]) -> dict:
        if self.base_url.startswith("mock://"):
            policy = self.base_url.removeprefix("mock://") or "vulnerable"
            if policy not in {"vulnerable", "careful"}:
                raise ValueError(f"unknown mock policy {policy!r}")
            return scripted_completion(messages, tools, cautious=policy == "careful")
        payload = chat_body(
            model=self.model,
            messages=messages,
            tools=tools,
            seed=self.seed,
            base_url=self.base_url,
            provider=self.provider,
            max_tokens=self.max_tokens,
        )
        headers = {"Authorization": f"Bearer {self.api_key}"}
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                if self.before_request is not None:
                    self.before_request()
                if self._client is not None:
                    response = self._client.post("/chat/completions", json=payload, headers=headers)
                else:
                    response = httpx.post(
                        self.base_url + "/chat/completions",
                        json=payload,
                        headers=headers,
                        timeout=self.timeout,
                        proxy=self.proxy,
                    )
                if response.status_code in {429, 502, 503, 504} and attempt < self.retries:
                    if response.status_code == 429 and self.retry_backoff > 0:
                        from a3p.hosted import backoff_seconds

                        self.sleeper(backoff_seconds(attempt, response.headers.get("retry-after")))
                    continue
                response.raise_for_status()
                body = response.json()
                if not isinstance(body, dict):
                    raise RuntimeError("chat completion was not a JSON object")
                usage = body.get("usage")
                if isinstance(usage, dict):
                    self.usage_events.append(usage)
                    if self.on_usage is not None:
                        self.on_usage(usage)
                return body
            except httpx.TimeoutException as exc:
                last_error = exc
                if attempt >= self.retries:
                    raise
        if last_error:
            raise last_error
        raise RuntimeError("chat completion failed")
