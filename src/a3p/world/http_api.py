"""Read-only HTTP checks: REST, Slack, Jira, and S3-compatible GET."""

from __future__ import annotations

import hashlib
import re
from typing import Any

import httpx

from a3p.world.base import Observation


def _client_get(
    client: httpx.Client | None,
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    if client is not None:
        return client.get(url, headers=headers)
    return httpx.get(url, headers=headers, timeout=20.0)


class RestVerifier:
    def __init__(self, *, client: httpx.Client | None = None) -> None:
        self.client = client
        self.name = "rest"

    def read(self, query: dict[str, Any]) -> Observation:
        method = str(query.get("method") or "GET").upper()
        url = str(query.get("url") or "")
        if method not in {"GET", "HEAD"}:
            return Observation(self.name, False, "only GET and HEAD are allowed", {"method": method})
        if not url.startswith(("http://", "https://")):
            return Observation(self.name, False, "url must be http or https", {})
        try:
            if method == "HEAD":
                if self.client is not None:
                    response = self.client.head(url)
                else:
                    response = httpx.head(url, timeout=20.0)
            else:
                response = _client_get(self.client, url)
        except httpx.HTTPError as exc:
            return Observation(self.name, False, f"{type(exc).__name__}: {exc}", {})
        expect = query.get("expect_status", 200)
        contains = query.get("contains")
        ok = response.status_code == int(expect)
        body = response.text
        if isinstance(contains, str) and contains not in body:
            ok = False
        summary = f"HTTP {response.status_code}"
        return Observation(self.name, ok, summary, {"status": response.status_code, "bytes": len(body)})


class SlackVerifier:
    def __init__(self, token: str, *, client: httpx.Client | None = None) -> None:
        self.token = token
        self.client = client
        self.name = "slack"

    def read(self, query: dict[str, Any]) -> Observation:
        channel = str(query.get("channel") or "")
        if not channel:
            return Observation(self.name, False, "channel is required", {})
        url = f"https://slack.com/api/conversations.history?channel={channel}&limit=50"
        try:
            response = _client_get(self.client, url, headers={"Authorization": f"Bearer {self.token}"})
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return Observation(self.name, False, f"{type(exc).__name__}: {exc}", {})
        if not isinstance(body, dict) or not body.get("ok"):
            return Observation(self.name, False, "Slack API did not return ok", {"body": body})
        raw_messages = body.get("messages")
        messages = raw_messages if isinstance(raw_messages, list) else []
        needle = str(query.get("text_contains") or "")
        hits = [item for item in messages if isinstance(item, dict) and (not needle or needle in str(item.get("text") or ""))]
        ok = len(hits) > 0 if needle else True
        return Observation(self.name, ok, f"{len(hits)} messages", {"count": len(hits)})


class JiraVerifier:
    def __init__(self, base_url: str, *, client: httpx.Client | None = None, token: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.token = token
        self.name = "jira"

    def read(self, query: dict[str, Any]) -> Observation:
        key = str(query.get("issue") or "")
        if not key or "/" in key:
            return Observation(self.name, False, "issue key is required", {})
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        url = f"{self.base_url}/rest/api/3/issue/{key}"
        try:
            response = _client_get(self.client, url, headers=headers)
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return Observation(self.name, False, f"{type(exc).__name__}: {exc}", {})
        if not isinstance(body, dict):
            return Observation(self.name, False, "issue was not an object", {})
        raw_fields = body.get("fields")
        fields = raw_fields if isinstance(raw_fields, dict) else {}
        raw_status = fields.get("status")
        status = raw_status if isinstance(raw_status, dict) else {}
        name = str(status.get("name") or "")
        expect = str(query.get("expect_status") or "")
        ok = bool(name) and (not expect or name.lower() == expect.lower())
        return Observation(self.name, ok, name or "issue has no status", {"status": name, "key": key})


class S3Verifier:
    """GET an object or list a bucket on an S3-compatible HTTP endpoint.

    Signing is the caller's header or a pre-signed URL. This is not the AWS SDK.
    """

    def __init__(self, endpoint: str, *, client: httpx.Client | None = None, headers: dict[str, str] | None = None) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.client = client
        self.headers = dict(headers or {})
        self.name = "s3"

    def read(self, query: dict[str, Any]) -> Observation:
        bucket = str(query.get("bucket") or "")
        key = str(query.get("key") or "")
        if not bucket or ".." in bucket or ".." in key:
            return Observation(self.name, False, "bucket is required", {})
        if key:
            url = f"{self.endpoint}/{bucket}/{key}"
            try:
                response = _client_get(self.client, url, headers=self.headers)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                return Observation(self.name, False, f"{type(exc).__name__}: {exc}", {})
            digest = hashlib.sha256(response.content).hexdigest()
            expect = str(query.get("sha256") or "")
            ok = not expect or expect == digest
            return Observation(self.name, ok, f"sha256 {digest[:12]}", {"sha256": digest, "key": key})
        url = f"{self.endpoint}/{bucket}?list-type=2"
        try:
            response = _client_get(self.client, url, headers=self.headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return Observation(self.name, False, f"{type(exc).__name__}: {exc}", {})
        keys = re.findall(r"<Key>([^<]+)</Key>", response.text)
        prefix = str(query.get("prefix") or "")
        if prefix:
            keys = [item for item in keys if item.startswith(prefix)]
        expect_key = str(query.get("expect_key") or "")
        ok = not expect_key or expect_key in keys
        return Observation(self.name, ok, f"{len(keys)} keys", {"keys": keys[:50]})
