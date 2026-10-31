"""Egress proxy.

Plain HTTP is forwarded. HTTPS to a pinned host (the provider that holds the
API key) is a TCP tunnel: the proxy records the host and redacts Authorization,
and it does not decrypt that path.

Other allow-listed hosts are intercepted when ``intercept`` is set. A per-run
CA signs a leaf for the CONNECT host. That CA is for the sandbox trust store
only. The probe process does not install it. SNI, the Host header, and an
optional path prefix list are enforced on the decrypted request. Bodies are
logged after redaction. Canaries and secrets in those bodies are findings,
not log lines.
"""

from __future__ import annotations

import ipaddress
import json
import os
import select
import socket
import ssl
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from a3p.canaries import redact

_ACTIVE_CA: str | None = None
_ACTIVE_LOCK = threading.Lock()


def current_ca() -> str | None:
    """CA path published by the intercept proxy on this process, if one is running."""
    with _ACTIVE_LOCK:
        return _ACTIVE_CA


def _set_active_ca(path: str | None) -> None:
    global _ACTIVE_CA
    with _ACTIVE_LOCK:
        _ACTIVE_CA = path


class EgressProxy:
    def __init__(
        self,
        allow: set[str],
        log_path: Path,
        *,
        intercept: bool = False,
        pin_hosts: set[str] | None = None,
        path_allow: dict[str, tuple[str, ...]] | None = None,
        canaries: tuple[str, ...] = (),
        upstream_ca: str | None = None,
    ) -> None:
        self.allow = {host.lower() for host in allow if host}
        self.pin_hosts = {host.lower() for host in (pin_hosts or set()) if host}
        self.path_allow = {host.lower(): prefixes for host, prefixes in (path_allow or {}).items()}
        self.canaries = tuple(item for item in canaries if item)
        self.intercept = intercept
        self.upstream_ca = upstream_ca
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.exfil_hits: list[dict[str, str]] = []
        self.ca_path: Path | None = None
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._dir: Path | None = None
        self._ca_cert: x509.Certificate | None = None
        self._ca_key: ec.EllipticCurvePrivateKey | None = None
        self._leaves: dict[str, tuple[Path, Path]] = {}
        self._lock = threading.Lock()

    @classmethod
    def for_base_url(cls, base_url: str, log_path: Path, *, intercept: bool = True) -> EgressProxy:
        """Allow one provider host, pin it, and intercept every other allow-listed host."""
        host = (urlsplit(base_url).hostname or "").lower()
        return cls({host}, log_path, intercept=intercept, pin_hosts={host})

    def start(self) -> str:
        if self.intercept:
            self._mint_ca()
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_CONNECT(self) -> None:  # noqa: N802
                host, port = _split_host(self.path, 443)
                pinned = proxy.pinned(host)
                proxy.record(
                    "CONNECT",
                    host,
                    self.headers.get("Proxy-Authorization"),
                    meta=None if not proxy.intercept else {"intercept": False, "pinned": pinned, "sni": host},
                )
                if not proxy.allowed(host):
                    self.send_error(403, "host is not on the egress allow-list")
                    return
                if proxy.intercept and not pinned:
                    self._intercept(host, port)
                    return
                self._tunnel(host, port)

            def do_GET(self) -> None:  # noqa: N802
                self._forward()

            def do_POST(self) -> None:  # noqa: N802
                self._forward()

            def _forward(self) -> None:
                parts = urlsplit(self.path)
                host = parts.hostname or ""
                proxy.record(self.command, host, self.headers.get("Authorization"))
                if not proxy.allowed(host):
                    self.send_error(403, "host is not on the egress allow-list")
                    return
                port = parts.port or (443 if parts.scheme == "https" else 80)
                length = int(self.headers.get("Content-Length") or "0")
                body = self.rfile.read(length) if length else b""
                path = parts.path or "/"
                if parts.query:
                    path = f"{path}?{parts.query}"
                header_lines = [f"{self.command} {path} HTTP/1.1", f"Host: {host}:{port}"]
                for key, value in self.headers.items():
                    if key.lower() in {"host", "proxy-connection", "proxy-authorization", "content-length"}:
                        continue
                    header_lines.append(f"{key}: {value}")
                if body:
                    header_lines.append(f"Content-Length: {len(body)}")
                raw = ("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii", "replace") + body
                self.close_connection = True
                try:
                    remote = socket.create_connection((host, port), timeout=5)
                except OSError:
                    self.send_error(502, "upstream connection failed")
                    return
                try:
                    remote.sendall(raw)
                    remote.shutdown(socket.SHUT_WR)
                    while True:
                        chunk = remote.recv(8192)
                        if not chunk:
                            break
                        self.connection.sendall(chunk)
                except OSError:
                    return
                finally:
                    remote.close()

            def _tunnel(self, host: str, port: int) -> None:
                try:
                    remote = socket.create_connection((host, port), timeout=5)
                except OSError:
                    self.send_error(502, "upstream connection failed")
                    return
                try:
                    self.send_response(200, "Connection Established")
                    self.end_headers()
                    _pump(self.connection, remote)
                finally:
                    remote.close()

            def _intercept(self, host: str, port: int) -> None:
                self.close_connection = True
                cert_path, key_path = proxy.leaf_for(host)
                self.send_response(200, "Connection Established")
                self.end_headers()
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
                expected = host.lower()

                def sni_cb(ssl_sock: ssl.SSLObject, server_name: str | None, ctx: ssl.SSLContext) -> int | None:
                    del ssl_sock, ctx
                    if server_name and server_name.lower() != expected:
                        return ssl.ALERT_DESCRIPTION_HANDSHAKE_FAILURE
                    if server_name and not proxy.allowed(server_name):
                        return ssl.ALERT_DESCRIPTION_HANDSHAKE_FAILURE
                    return None

                context.sni_callback = sni_cb
                try:
                    client = context.wrap_socket(self.connection, server_side=True)
                except ssl.SSLError:
                    return
                try:
                    _exchange(proxy, client, host, port)
                finally:
                    try:
                        client.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    client.close()

            def log_message(self, fmt: str, *args: object) -> None:
                del fmt, args

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        self._httpd = server
        self._thread = threading.Thread(target=server.serve_forever, name="a3p-egress", daemon=True)
        self._thread.start()
        port = int(server.server_address[1])
        return f"http://127.0.0.1:{port}"

    def stop(self) -> None:
        if self.ca_path is not None and current_ca() == str(self.ca_path):
            _set_active_ca(None)
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        self._ca_key = None

    def allowed(self, host: str) -> bool:
        return host.lower() in self.allow

    def pinned(self, host: str) -> bool:
        return host.lower() in self.pin_hosts

    def path_allowed(self, host: str, path: str) -> bool:
        prefixes = self.path_allow.get(host.lower())
        if not prefixes:
            return True
        clean = path.split("?", 1)[0]
        return any(_prefix_ok(clean, prefix) for prefix in prefixes)

    def record(
        self,
        method: str,
        host: str,
        authorization: str | None,
        *,
        meta: dict[str, Any] | None = None,
    ) -> None:
        marker = "[redacted]" if authorization else "absent"
        line = f"{method} host={host} authorization={marker}\n"
        if authorization and authorization in line:
            line = f"{method} host={host} authorization=[redacted]\n"
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            if meta is not None:
                safe = _scrub_meta(self, meta)
                handle.write(json.dumps(safe, sort_keys=True) + "\n")

    def note_exfil(self, host: str, where: str, needle: str) -> None:
        self.exfil_hits.append({"host": host, "where": where, "needle": needle})

    def scrub(self, text: str) -> str:
        cleaned = redact(text or "")
        for needle in self.canaries:
            if needle and needle in cleaned:
                cleaned = cleaned.replace(needle, "[redacted-canary]")
        return cleaned

    def leaf_for(self, host: str) -> tuple[Path, Path]:
        key = host.lower()
        with self._lock:
            found = self._leaves.get(key)
            if found is not None:
                return found
            if self._ca_cert is None or self._ca_key is None or self._dir is None:
                raise RuntimeError("intercept CA was not minted")
            cert_pem, key_pem = issue_leaf(self._ca_cert, self._ca_key, host)
            cert_path = self._dir / f"{_safe(host)}.crt"
            key_path = self._dir / f"{_safe(host)}.key"
            _write_secret(key_path, key_pem)
            cert_path.write_bytes(cert_pem)
            self._leaves[key] = (cert_path, key_path)
            return cert_path, key_path

    def _mint_ca(self) -> None:
        self._dir = Path(tempfile.mkdtemp(prefix="a3p-ca-"))
        cert, key = issue_ca()
        self._ca_cert = cert
        self._ca_key = key
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.ca_path = self._dir / "ca.pem"
        _write_secret(self._dir / "ca.key", key_pem)
        self.ca_path.write_bytes(cert_pem)
        _set_active_ca(str(self.ca_path))


def issue_ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "A3P ephemeral intercept CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def issue_leaf(
    ca_cert: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    hostname: str,
) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])])
    now = datetime.now(UTC)
    try:
        san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san = x509.DNSName(hostname)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def _exchange(proxy: EgressProxy, client: ssl.SSLSocket, host: str, port: int) -> None:
    raw = _read_message(client)
    if not raw:
        return
    method, path, headers, body = _parse_http(raw)
    header_host = _header(headers, "host")
    if _host_name(header_host) != host.lower():
        _reply(client, 403, b"host header does not match SNI")
        proxy.record(
            method or "GET",
            host,
            None,
            meta={"intercept": True, "sni": host, "path": path, "status": 403, "reason": "host-mismatch"},
        )
        return
    if not proxy.path_allowed(host, path):
        _reply(client, 403, b"path is not on the egress allow-list")
        proxy.record(
            method or "GET",
            host,
            None,
            meta={"intercept": True, "sni": host, "path": path, "status": 403, "reason": "path"},
        )
        return
    request_text = body.decode("utf-8", "replace")
    _scan(proxy, host, "request", request_text + "\n" + path)
    upstream = _open_upstream(proxy, host, port)
    if upstream is None:
        _reply(client, 502, b"upstream connection failed")
        return
    try:
        upstream.sendall(_rewrite(method, path, headers, body, host, port))
        response = _read_message(upstream)
    except OSError:
        _reply(client, 502, b"upstream connection failed")
        return
    finally:
        upstream.close()
    status = _status_code(response)
    response_body = response.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in response else b""
    response_text = response_body.decode("utf-8", "replace")
    _scan(proxy, host, "response", response_text)
    proxy.record(
        method or "GET",
        host,
        _header(headers, "authorization") or None,
        meta={
            "intercept": True,
            "sni": host,
            "path": path,
            "status": status,
            "request_body": request_text[:2000],
            "response_body": response_text[:2000],
        },
    )
    try:
        client.sendall(response)
    except OSError:
        return


def _open_upstream(proxy: EgressProxy, host: str, port: int) -> ssl.SSLSocket | None:
    try:
        raw = socket.create_connection((host, port), timeout=5)
    except OSError:
        return None
    context = ssl.create_default_context()
    if proxy.upstream_ca:
        context.load_verify_locations(proxy.upstream_ca)
    try:
        return context.wrap_socket(raw, server_hostname=host)
    except ssl.SSLError:
        raw.close()
        return None


def _scan(proxy: EgressProxy, host: str, where: str, text: str) -> None:
    for needle in proxy.canaries:
        if needle and needle in text:
            proxy.note_exfil(host, where, needle)
    redacted = redact(text)
    if redacted != text:
        proxy.note_exfil(host, where, "secret")


def _scrub_meta(proxy: EgressProxy, meta: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in meta.items():
        if key in {"request_body", "response_body"} and isinstance(value, str):
            safe[key] = proxy.scrub(value)[:2000]
        elif key == "authorization":
            safe[key] = "[redacted]"
        else:
            safe[key] = value
    safe["exfil"] = len(proxy.exfil_hits)
    return safe


def _rewrite(method: str, path: str, headers: list[tuple[str, str]], body: bytes, host: str, port: int) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}:{port}"]
    for key, value in headers:
        lowered = key.lower()
        if lowered in {"host", "proxy-connection", "proxy-authorization", "content-length", "connection"}:
            continue
        if lowered == "authorization":
            lines.append(f"{key}: {value}")
            continue
        lines.append(f"{key}: {value}")
    lines.append("Connection: close")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii", "replace") + body


def _reply(sock: ssl.SSLSocket, status: int, body: bytes) -> None:
    reason = "Forbidden" if status == 403 else "Bad Gateway"
    raw = (
        f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode("ascii") + body
    try:
        sock.sendall(raw)
    except OSError:
        return


def _read_message(sock: socket.socket, limit: int = 65536) -> bytes:
    sock.settimeout(5)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < limit:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
    head, sep, rest = data.partition(b"\r\n\r\n")
    if not sep:
        return data
    length = 0
    for line in head.decode("iso-8859-1", "replace").split("\r\n")[1:]:
        if line.lower().startswith("content-length:"):
            try:
                length = int(line.split(":", 1)[1].strip())
            except ValueError:
                length = 0
    while len(rest) < length and len(head) + 4 + len(rest) < limit:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        rest += chunk
    if length:
        rest = rest[:length]
    return head + b"\r\n\r\n" + rest


def _parse_http(raw: bytes) -> tuple[str, str, list[tuple[str, str]], bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    parts = (lines[0] if lines else "").split(" ")
    method = parts[0] if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers.append((key.strip(), value.strip()))
    return method, path, headers, body


def _header(headers: list[tuple[str, str]], name: str) -> str:
    for key, value in headers:
        if key.lower() == name:
            return value
    return ""


def _status_code(raw: bytes) -> int:
    line = raw.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
    parts = line.split(" ")
    if len(parts) < 2:
        return 0
    try:
        return int(parts[1])
    except ValueError:
        return 0


def _host_name(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("["):
        end = text.find("]")
        return text[1:end] if end > 1 else text
    if text.count(":") == 1:
        return text.split(":", 1)[0]
    return text


def _prefix_ok(path: str, prefix: str) -> bool:
    if path == prefix:
        return True
    base = prefix if prefix.endswith("/") else prefix + "/"
    return path.startswith(base)


def _safe(host: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in host)[:80]


def _write_secret(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)


def _split_host(path: str, default_port: int) -> tuple[str, int]:
    host, sep, port_text = path.partition(":")
    if not sep:
        return host, default_port
    try:
        return host, int(port_text)
    except ValueError:
        return host, default_port


def _pump(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    left.setblocking(False)
    right.setblocking(False)
    while sockets:
        readable, _, _ = select.select(sockets, [], [], 5)
        if not readable:
            break
        for source in readable:
            other = right if source is left else left
            try:
                chunk = source.recv(8192)
            except OSError:
                return
            if not chunk:
                return
            try:
                other.sendall(chunk)
            except OSError:
                return
