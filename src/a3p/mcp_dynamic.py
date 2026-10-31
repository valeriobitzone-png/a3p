"""Launch an MCP server inside the tool sandbox and record what it exposes.

Stdio is a pipe into the sandbox. The command is the one the operator names,
or the vulnerable demo when no command is given. HTTP/SSE and Streamable HTTP
use a unix socket on a read-write mount so the server can stay off the IP
network. A server that only binds loopback TCP is reached by ``a3p.mcp_bridge``
in the same sandbox, which copies bytes to ``127.0.0.1`` and does not open a route.
Streamable HTTP is one POST endpoint (``/mcp``) that answers JSON-RPC with
``application/json``. The demo answers GET ``/mcp`` with 405, which the spec
allows when the server does not push its own stream.

The scan re-lists tools and diffs description hashes (a rug pull), reads
resources and prompts, and sends archive probes to tools that are not marked
destructive. Destructive tools are called only when the operator opts in.
The demo's shell records a fake effect and does not execute a command. A
third-party tool still runs its own code inside the sandbox. A finding is
evidence about this server, not a certification.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from a3p.isolation import SandboxProcess, best_level, configured_level, popen_sandboxed
from a3p.ledger import LedgerWriter
from a3p.mcp_static import POISON_PHRASES, tool_fingerprint
from a3p.mcp_vulnerable import encode_message, read_message

_SECRET = re.compile(r"sk-[A-Za-z0-9_-]{8,}|A3P-SECRET-[A-Za-z0-9-]+|-----BEGIN [A-Z ]+PRIVATE KEY-----")
_DESTRUCTIVE_NAMES = {"shell", "exec", "delete", "drop", "eval"}


class McpScanError(RuntimeError):
    pass


class McpSession(Protocol):
    def request(self, method: str, params: dict[str, Any] | None = None) -> Any: ...

    def notify(self, method: str) -> None: ...

    def close(self) -> None: ...


class StdioSession:
    def __init__(self, sandbox: SandboxProcess) -> None:
        self.sandbox = sandbox
        self._seq = 0
        if sandbox.process.stdin is None or sandbox.process.stdout is None:
            raise McpScanError("sandbox stdio is closed")
        self._stdin = sandbox.process.stdin
        self._stdout = sandbox.process.stdout

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._seq += 1
        ident = self._seq
        self._send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params or {}})
        while True:
            try:
                message = read_message(self._stdout)
            except (EOFError, ValueError, json.JSONDecodeError) as exc:
                raise McpScanError(f"stdio closed during {method}: {exc}") from exc
            if message.get("id") != ident:
                continue
            if message.get("error"):
                raise McpScanError(str(message["error"]))
            return message.get("result")

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def close(self) -> None:
        self.sandbox.close()

    def _send(self, message: dict[str, Any]) -> None:
        self._stdin.write(encode_message(message))
        self._stdin.flush()


class SseSession:
    def __init__(self, base_url: str, *, uds: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.uds = uds
        self._seq = 0
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._responses: Queue[dict[str, Any]] = Queue()
        self._stream = httpx.Client(transport=self._transport(), timeout=120.0)
        self._post = httpx.Client(transport=self._transport(), timeout=20.0)
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=15):
            self.close()
            raise McpScanError("SSE endpoint was not announced")

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._seq += 1
        ident = self._seq
        response = self._post.post(
            self.base_url + "/messages",
            json={"jsonrpc": "2.0", "id": ident, "method": method, "params": params or {}},
        )
        response.raise_for_status()
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                message = self._responses.get(timeout=0.2)
            except Empty:
                continue
            if message.get("id") != ident:
                continue
            if message.get("error"):
                raise McpScanError(str(message["error"]))
            return message.get("result")
        raise McpScanError(f"no SSE response for {method}")

    def notify(self, method: str) -> None:
        response = self._post.post(self.base_url + "/messages", json={"jsonrpc": "2.0", "method": method})
        response.raise_for_status()

    def close(self) -> None:
        self._closed.set()
        self._stream.close()
        self._post.close()

    def _transport(self) -> httpx.BaseTransport | None:
        if self.uds:
            return httpx.HTTPTransport(uds=self.uds)
        return None

    def _read(self) -> None:
        deadline = time.time() + 15
        while time.time() < deadline and not self._ready.is_set() and not self._closed.is_set():
            event = ""
            data = ""
            try:
                with self._stream.stream("GET", self.base_url + "/sse") as response:
                    response.raise_for_status()
                    for line in response.iter_lines():
                        if line == "":
                            if event == "endpoint":
                                self._ready.set()
                            elif event == "message" and data:
                                parsed = json.loads(data)
                                if isinstance(parsed, dict):
                                    self._responses.put(parsed)
                            event = ""
                            data = ""
                            continue
                        if line.startswith("event:"):
                            event = line.split(":", 1)[1].strip()
                        elif line.startswith("data:"):
                            data = line.split(":", 1)[1].strip()
            except (httpx.HTTPError, json.JSONDecodeError, OSError):
                time.sleep(0.05)


class StreamableSession:
    """MCP Streamable HTTP: POST ``/mcp``, JSON response, optional session id."""

    def __init__(self, base_url: str, *, uds: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._seq = 0
        self._session = ""
        transport = httpx.HTTPTransport(uds=uds) if uds else None
        self._client = httpx.Client(transport=transport, timeout=30.0)

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._seq += 1
        body_params = dict(params or {})
        if method == "initialize":
            body_params["protocolVersion"] = "2025-03-26"
        message = self._post(
            {"jsonrpc": "2.0", "id": self._seq, "method": method, "params": body_params}
        )
        if message.get("error"):
            raise McpScanError(str(message["error"]))
        return message.get("result")

    def notify(self, method: str) -> None:
        self._post({"jsonrpc": "2.0", "method": method}, expect_json=False)

    def close(self) -> None:
        self._client.close()

    def _post(self, payload: dict[str, Any], *, expect_json: bool = True) -> dict[str, Any]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-03-26",
        }
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        response = self._client.post(self.base_url + "/mcp", json=payload, headers=headers)
        response.raise_for_status()
        session = response.headers.get("Mcp-Session-Id") or ""
        if session:
            self._session = session
        if not expect_json:
            return {}
        ctype = response.headers.get("content-type") or ""
        if "text/event-stream" in ctype:
            return _sse_payload(response.text)
        parsed = response.json()
        if not isinstance(parsed, dict):
            raise McpScanError("streamable HTTP response was not an object")
        return parsed


def _sse_payload(body: str) -> dict[str, Any]:
    data = ""
    for line in body.splitlines():
        if line.startswith("data:"):
            data = line.split(":", 1)[1].strip()
    if not data:
        raise McpScanError("streamable HTTP event had no data")
    parsed = json.loads(data)
    if not isinstance(parsed, dict):
        raise McpScanError("streamable HTTP event was not an object")
    return parsed


def parse_probe_limit(raw: str) -> int | None:
    """``all`` means every local archive row. A positive integer is a slice."""
    text = raw.strip().casefold()
    if text == "all":
        return None
    if not text.isdigit() or int(text) < 1:
        raise McpScanError("--probe must be a positive integer or all")
    return int(text)


def archive_probes(seed: int, limit: int | None = 3) -> list[dict[str, str]]:
    """A deterministic slice of the local attack archive. Nothing is downloaded.

    ``limit is None`` keeps every row, in archive order. A positive limit uses
    the seeded quick sample.
    """
    from a3p.corpus import load_archive, sample_cases

    cases = load_archive()
    chosen = cases if limit is None else sample_cases(cases, "quick", seed=seed, limit=max(limit, 1))[:limit]
    probes: list[dict[str, str]] = []
    for case in chosen:
        probes.append(
            {
                "id": str(case.get("id") or ""),
                "language": str(case.get("language") or ""),
                "text": str(case.get("text") or "")[:180],
            }
        )
    return probes


def split_command(text: str) -> list[str]:
    """Split a command the way a shell would, without invoking a shell."""
    try:
        parts = shlex.split(text)
    except ValueError as exc:
        raise McpScanError(f"command could not be parsed: {exc}") from exc
    if not parts:
        raise McpScanError("command is empty")
    return parts


def loopback_port(url: str) -> int:
    """Port of a loopback URL. Other hosts are refused so the probe does not dial them."""
    parsed = urlsplit(url)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise McpScanError("the scan only bridges loopback inside the sandbox")
    if parsed.port is None:
        raise McpScanError("URL needs a port")
    return int(parsed.port)


_DENIED = {"container", "bwrap", "nsjail", "runsc"}


def resolve_sandbox(name: str, *, allow_process: bool) -> str:
    """Pick a jail. ``process`` runs only when the operator sets the unsafe flag.

    ``auto`` follows ``A3P_ISOLATION`` when that names a jail, so ``nsjail`` or
    ``runsc`` wins even if Docker is installed. An in-process handler setting
    does not apply to this scan; ``auto`` then uses :func:`best_level`.
    """
    if name == "auto":
        chosen = configured_level()
        if chosen in {"inprocess", "auto", ""}:
            chosen = best_level()
        if chosen == "process" and not allow_process:
            raise McpScanError("process sandbox is refused unless --unsafe-process-sandbox is set")
        if chosen == "unavailable":
            if allow_process:
                return "process"
            raise McpScanError(
                "no container, gVisor, nsjail, or bubblewrap is available; "
                "pass --unsafe-process-sandbox to use a subprocess"
            )
        return chosen
    if name == "process" and not allow_process:
        raise McpScanError("process sandbox is refused unless --unsafe-process-sandbox is set")
    if name not in {"container", "runsc", "nsjail", "bwrap", "process"}:
        raise McpScanError(f"unsupported sandbox {name}")
    return name


def _excessive(tool: dict[str, Any]) -> bool:
    name = str(tool.get("name") or "").casefold()
    raw_annotations = tool.get("annotations")
    annotations: dict[str, Any] = raw_annotations if isinstance(raw_annotations, dict) else {}
    if annotations.get("destructiveHint") is True:
        return True
    return name in _DESTRUCTIVE_NAMES


def _texts(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            found.extend(_texts(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_texts(item))
    return found


def _poisoned(text: str) -> str | None:
    lowered = text.casefold()
    for phrase in POISON_PHRASES:
        if phrase in lowered:
            return phrase
    return None


def _secret(text: str) -> str | None:
    match = _SECRET.search(text)
    if not match:
        return None
    token = match.group(0)
    return token[:6] + "…"


def scan_session(
    session: McpSession,
    probes: list[dict[str, str]],
    *,
    invoke_destructive: bool = False,
) -> dict[str, Any]:
    session.request(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "a3p-mcp-scan", "version": "0"},
        },
    )
    session.notify("notifications/initialized")
    first = _tools(session.request("tools/list"))
    second = _tools(session.request("tools/list"))
    findings: list[dict[str, str]] = []
    for tool in first:
        phrase = _poisoned(str(tool.get("description") or ""))
        if phrase:
            findings.append(
                {
                    "kind": "poisoning",
                    "name": str(tool.get("name") or ""),
                    "summary": f"description contains {phrase!r}",
                }
            )
        if _excessive(tool):
            _destructive(session, tool, findings, invoke_destructive)
    first_hash = {str(tool.get("name") or ""): tool_fingerprint(tool) for tool in first}
    second_hash = {str(tool.get("name") or ""): tool_fingerprint(tool) for tool in second}
    for name, digest in second_hash.items():
        pinned = first_hash.get(name)
        if pinned is not None and pinned != digest:
            findings.append(
                {
                    "kind": "rug-pull",
                    "name": name,
                    "summary": f"description hash changed for {name}",
                    "sha256": digest,
                    "pinned": pinned,
                }
            )
    for name in first_hash:
        if name not in second_hash:
            findings.append({"kind": "rug-pull", "name": name, "summary": f"{name} disappeared on re-list"})
    for tool in first:
        if _excessive(tool):
            continue
        name = str(tool.get("name") or "")
        for probe in probes:
            result = session.request("tools/call", {"name": name, "arguments": {"q": probe.get("text") or ""}})
            _collect_output(findings, name, result, f"tool {name} probe {probe.get('id') or ''}")
    resources = _named(session.request("resources/list"), "resources", "uri")
    for uri in resources:
        _collect_output(findings, uri, session.request("resources/read", {"uri": uri}), f"resource {uri}")
    prompts = _named(session.request("prompts/list"), "prompts", "name")
    for name in prompts:
        listed = session.request("prompts/list")
        for item in _rows(listed, "prompts"):
            if str(item.get("name") or "") == name:
                phrase = _poisoned(str(item.get("description") or ""))
                if phrase:
                    findings.append({"kind": "injection", "name": name, "summary": f"prompt description contains {phrase!r}"})
        _collect_output(findings, name, session.request("prompts/get", {"name": name}), f"prompt {name}")
    return {
        "findings": findings,
        "tools": [str(tool.get("name") or "") for tool in first],
        "resources": resources,
        "prompts": prompts,
    }


def _destructive(
    session: McpSession,
    tool: dict[str, Any],
    findings: list[dict[str, str]],
    invoke: bool,
) -> None:
    name = str(tool.get("name") or "")
    if not invoke:
        findings.append(
            {
                "kind": "excessive-permission",
                "name": name,
                "summary": "destructive tool was listed and was not invoked",
            }
        )
        return
    result = session.request(
        "tools/call",
        {"name": name, "arguments": {"cmd": "a3p-fake-noop", "q": "a3p-fake-noop"}},
    )
    fake = any("not executed" in text for text in _texts(result))
    findings.append(
        {
            "kind": "destructive-invoked",
            "name": name,
            "summary": (
                "fake side effect recorded inside the sandbox; the command was not executed"
                if fake
                else "invoked inside the sandbox; a third-party tool still runs its own code there"
            ),
        }
    )
    _collect_output(findings, name, result, f"destructive {name}")


def _tools(result: Any) -> list[dict[str, Any]]:
    if not isinstance(result, dict):
        raise McpScanError("tools/list was not an object")
    return [item for item in result.get("tools") or [] if isinstance(item, dict)]


def _rows(result: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(result, dict):
        return []
    return [item for item in result.get(key) or [] if isinstance(item, dict)]


def _named(result: Any, key: str, field: str) -> list[str]:
    return [str(item.get(field) or "") for item in _rows(result, key) if item.get(field)]


def _collect_output(findings: list[dict[str, str]], name: str, result: Any, where: str) -> None:
    for text in _texts(result):
        phrase = _poisoned(text)
        if phrase:
            findings.append({"kind": "injection", "name": name, "summary": f"{where} contains {phrase!r}"})
        secret = _secret(text)
        if secret:
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            findings.append(
                {
                    "kind": "secret",
                    "name": name,
                    "summary": f"{where} matched a secret pattern ({secret})",
                    "sha256": digest,
                }
            )


def run_live_scan(
    *,
    level: str,
    transport: str,
    output: Path,
    seed: int = 0,
    probes: list[dict[str, str]] | None = None,
    probe_limit: int | None = 3,
    command: list[str] | None = None,
    tcp_port: int | None = None,
    server_env: dict[str, str] | None = None,
    invoke_destructive: bool = False,
    allow_process: bool = False,
) -> dict[str, Any]:
    if transport not in {"stdio", "sse", "streamable"}:
        raise McpScanError(f"unsupported transport {transport}")
    chosen_level = resolve_sandbox(level, allow_process=allow_process)
    chosen = list(probes) if probes is not None else archive_probes(seed, probe_limit)
    session = _open_session(chosen_level, transport, command, tcp_port, server_env)
    started = time.perf_counter()
    try:
        scanned = scan_session(session, chosen, invoke_destructive=invoke_destructive)
    finally:
        session.close()
    elapsed = round(time.perf_counter() - started, 3)
    if invoke_destructive:
        destructive_note = (
            "Destructive tools were invoked inside the sandbox. "
            "The demo records a fake effect and does not execute a command. "
            "A third-party tool still runs its own code there. "
        )
    else:
        destructive_note = "Destructive tools were not invoked. "
    report = {
        "transport": transport,
        "sandbox": chosen_level,
        "network": "denied" if chosen_level in _DENIED else "open",
        "command": command or ["-m", "a3p.mcp_vulnerable"],
        "tcp_port": tcp_port,
        "probes": [{"id": item.get("id", ""), "language": item.get("language", "")} for item in chosen],
        "elapsed_s": elapsed,
        "note": (
            destructive_note
            + "Container, gVisor, nsjail, and bubblewrap have no IP network. "
            "A TCP server is reached through a unix-socket bridge to loopback inside the sandbox. "
            "This scan is one sample, not a certification."
        ),
        **scanned,
    }
    report["ledger_head"] = _seal(output, report)
    return report


def _open_session(
    level: str,
    transport: str,
    command: list[str] | None,
    tcp_port: int | None,
    server_env: dict[str, str] | None,
) -> McpSession:
    if transport == "stdio":
        if tcp_port is not None:
            raise McpScanError("a TCP bridge is for HTTP transports, not stdio")
        if command is None:
            return _stdio_session(level, server_env)
        return _stdio_command(level, command, server_env)
    if transport not in {"sse", "streamable"}:
        raise McpScanError(f"unsupported transport {transport}")
    if tcp_port is not None:
        return _tcp_session(level, tcp_port, command, server_env, transport)
    if command is not None:
        raise McpScanError("an HTTP command needs a loopback URL so the bridge knows the port")
    return _http_session(level, transport)


def _stdio_session(level: str, server_env: dict[str, str] | None) -> StdioSession:
    sandbox = popen_sandboxed(level, ["-m", "a3p.mcp_vulnerable"], extra_env=server_env)
    return StdioSession(sandbox)


def _stdio_command(level: str, command: list[str], server_env: dict[str, str] | None) -> StdioSession:
    sandbox = popen_sandboxed(level, _absolute_argv(command, level), extra_env=server_env, interpreter=False)
    return StdioSession(sandbox)


def _absolute_argv(command: list[str], level: str) -> list[str]:
    argv = list(command)
    if not argv:
        raise McpScanError("command is empty")
    if level != "process" and argv[0] == sys.executable:
        argv[0] = "/usr/bin/python3"
    if not str(argv[0]).startswith("/"):
        found = shutil.which(argv[0])
        if not found or not str(found).startswith("/"):
            raise McpScanError("command must be an absolute path inside the sandbox")
        argv[0] = found
    return argv


class BoundSession:
    """An HTTP session plus the sandbox that owns the server socket."""

    def __init__(self, inner: McpSession, sandbox: SandboxProcess) -> None:
        self.inner = inner
        self.sandbox = sandbox

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        return self.inner.request(method, params)

    def notify(self, method: str) -> None:
        self.inner.notify(method)

    def close(self) -> None:
        self.inner.close()
        self.sandbox.close()


def _http_session(level: str, transport: str) -> BoundSession:
    import tempfile

    sock_dir = Path(tempfile.mkdtemp(prefix="a3p-mcp-sock-"))
    mode = "streamable" if transport == "streamable" else "sse"
    if level == "process":
        uds = sock_dir / "mcp.sock"
        sandbox = popen_sandboxed(
            level,
            ["-m", "a3p.mcp_vulnerable"],
            extra_env={"A3P_MCP_UDS": str(uds), "A3P_MCP_MODE": mode},
        )
        visible = uds
    else:
        sandbox = popen_sandboxed(
            level,
            ["-m", "a3p.mcp_vulnerable"],
            extra_env={"A3P_MCP_UDS": "/opt/a3p-rw/mcp.sock", "A3P_MCP_MODE": mode},
            rw_mount=(sock_dir, "/opt/a3p-rw"),
        )
        visible = sock_dir / "mcp.sock"
    try:
        _wait_for(visible, sandbox)
        if transport == "streamable":
            session: McpSession = StreamableSession("http://localhost", uds=str(visible))
        else:
            session = SseSession("http://localhost", uds=str(visible))
    except Exception:
        sandbox.close()
        raise
    return BoundSession(session, sandbox)


def _sse_session(level: str) -> BoundSession:
    return _http_session(level, "sse")


def _tcp_session(
    level: str,
    port: int,
    command: list[str] | None,
    server_env: dict[str, str] | None,
    transport: str = "sse",
) -> BoundSession:
    """Bridge a unix socket to loopback TCP inside the same sandbox."""
    import tempfile

    if not 1 <= port <= 65535:
        raise McpScanError("tcp port out of range")
    child = _absolute_argv(command or [sys.executable, "-m", "a3p.mcp_vulnerable"], level)
    env = dict(server_env or {})
    if command is None:
        env["A3P_MCP_SSE_PORT"] = str(port)
        env["A3P_MCP_MODE"] = "streamable" if transport == "streamable" else "sse"
    sock_dir = Path(tempfile.mkdtemp(prefix="a3p-mcp-sock-"))
    if level == "process":
        listen = str(sock_dir / "mcp.sock")
        visible = Path(listen)
        mount = None
    else:
        listen = "/opt/a3p-rw/mcp.sock"
        visible = sock_dir / "mcp.sock"
        mount = (sock_dir, "/opt/a3p-rw")
    program = ["-m", "a3p.mcp_bridge", "--listen", listen, "--target", f"127.0.0.1:{port}", "--", *child]
    sandbox = popen_sandboxed(level, program, extra_env=env, rw_mount=mount, interpreter=True)
    try:
        _wait_for(visible, sandbox)
        if transport == "streamable":
            bridged: McpSession = StreamableSession("http://localhost", uds=str(visible))
        else:
            bridged = SseSession("http://localhost", uds=str(visible))
    except Exception:
        sandbox.close()
        raise
    return BoundSession(bridged, sandbox)


def _wait_for(path: Path, sandbox: SandboxProcess) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        if path.exists():
            return
        if sandbox.process.poll() is not None:
            err = ""
            if sandbox.process.stderr is not None:
                err = sandbox.process.stderr.read().decode("utf-8", errors="replace")
            raise McpScanError(err.strip() or "MCP server exited before the socket appeared")
        time.sleep(0.05)
    raise McpScanError("MCP unix socket did not appear")


def _seal(output: Path, report: dict[str, Any]) -> str:
    writer = LedgerWriter(output)
    writer.append(
        "mcp-live-scan",
        {
            "transport": report["transport"],
            "sandbox": report["sandbox"],
            "network": report["network"],
            "tools": report["tools"],
            "resources": report["resources"],
            "prompts": report["prompts"],
            "probes": report["probes"],
            "note": report["note"],
        },
    )
    for finding in report["findings"]:
        writer.append("mcp-finding", dict(finding))
    sealed = writer.seal()
    (output / "mcp-scan.json").write_text(json.dumps(report_public(report), indent=2) + "\n", encoding="utf-8")
    return sealed.head


def report_public(report: dict[str, Any]) -> dict[str, Any]:
    """Drop the ledger head cycle: the file is the scan, the ledger is the seal."""
    copied = dict(report)
    copied.pop("ledger_head", None)
    return copied
