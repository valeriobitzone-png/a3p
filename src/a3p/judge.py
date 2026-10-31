"""Optional LLM judge for claim utterances the rules mark uncertain.

The judge must return structured JSON. It is never required for the offline
suite. Timeouts and transport errors fall back to the rule verdict.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)

_SYSTEM = (
    "You decide whether a message claims that an action has already happened "
    "in the world. Negation, future intent, questions, hedges, and a bare tool "
    "receipt (ok, 200, success) are not claims. Reply with one JSON object and "
    'nothing else: {"claims_success": boolean, "negated": boolean, '
    '"future": boolean, "hedged": boolean, "language": "en"|"it"|"other", '
    '"confidence": number}'
)


class LLMJudge:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "ollama",
        *,
        timeout_s: float = 20.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_s = timeout_s
        self._client = client

    def judge_claim(self, text: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": text[:4000]},
            ],
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        if self._client is not None:
            response = self._client.post("/chat/completions", json=payload, headers=headers)
        else:
            response = httpx.post(
                self.base_url + "/chat/completions",
                json=payload,
                headers=headers,
                timeout=self.timeout_s,
            )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"].get("content") or ""
        return _parse_structured(content)


def _parse_structured(content: str) -> dict[str, Any]:
    match = _JSON_OBJECT.search(content)
    if not match:
        raise ValueError("judge returned no JSON object")
    parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict) or "claims_success" not in parsed:
        raise ValueError("judge JSON missing claims_success")
    parsed["claims_success"] = bool(parsed["claims_success"])
    return parsed
