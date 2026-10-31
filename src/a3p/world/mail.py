"""Mailbox, a local SMTP sink, and IMAP. All three are reads of mail the probe holds."""

from __future__ import annotations

import mailbox
import socket
import threading
from email import message_from_bytes
from email.message import Message
from pathlib import Path
from typing import Any

import httpx

from a3p.world.base import Observation


def _match(message: Message, query: dict[str, Any]) -> bool:
    to = str(query.get("to") or "")
    subject = str(query.get("subject_contains") or "")
    body = str(query.get("body_contains") or "")
    if to and to.lower() not in str(message.get("To") or "").lower():
        return False
    if subject and subject.lower() not in str(message.get("Subject") or "").lower():
        return False
    if body and body not in str(message.get_payload() or ""):
        return False
    return True


def _observation(name: str, messages: list[Message], query: dict[str, Any]) -> Observation:
    hits = [item for item in messages if _match(item, query)]
    expect = query.get("expect_count")
    ok = len(hits) > 0 if expect is None else len(hits) == int(expect)
    summary = f"{len(hits)} matching messages"
    if not ok:
        summary = f"{len(hits)} matching messages, expected {expect if expect is not None else 'at least 1'}"
    subjects = [str(item.get("Subject") or "") for item in hits[:20]]
    return Observation(name, ok, summary, {"count": len(hits), "subjects": subjects})


class MailboxVerifier:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.name = "mailbox"

    def read(self, query: dict[str, Any]) -> Observation:
        if self.path.is_dir():
            messages = []
            for item in sorted(self.path.glob("*.eml")):
                messages.append(message_from_bytes(item.read_bytes()))
        elif self.path.is_file():
            box = mailbox.mbox(self.path)
            try:
                messages = [message for message in box]
            finally:
                box.close()
        else:
            return Observation(self.name, False, "mailbox path is missing", {})
        return _observation(self.name, messages, query)


class SmtpSink:
    """Accept SMTP on localhost and keep the messages for a later read."""

    def __init__(self) -> None:
        self.name = "smtp-sink"
        self.messages: list[Message] = []
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.port = 0

    def start(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(5)
        self._socket = sock
        self.port = int(sock.getsockname()[1])
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        sock = self._socket
        self._socket = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def read(self, query: dict[str, Any]) -> Observation:
        return _observation(self.name, list(self.messages), query)

    def _accept(self) -> None:
        sock = self._socket
        if sock is None:
            return
        while self._socket is not None:
            try:
                conn, _addr = sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn: socket.socket) -> None:
        try:
            conn.sendall(b"220 a3p sink\r\n")
            buffer = b""
            collecting = False
            data = bytearray()
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                buffer += chunk
                while b"\r\n" in buffer:
                    line, buffer = buffer.split(b"\r\n", 1)
                    if collecting:
                        if line == b".":
                            self.messages.append(message_from_bytes(bytes(data)))
                            data.clear()
                            collecting = False
                            conn.sendall(b"250 OK\r\n")
                        else:
                            data.extend(line + b"\n")
                        continue
                    verb = line.split(b" ", 1)[0].upper()
                    if verb == b"DATA":
                        collecting = True
                        conn.sendall(b"354 send the message\r\n")
                    elif verb == b"QUIT":
                        conn.sendall(b"221 bye\r\n")
                        return
                    else:
                        conn.sendall(b"250 OK\r\n")
        except OSError:
            return
        finally:
            conn.close()


class ImapVerifier:
    """Read INBOX over IMAP. Tests can pass an already connected client."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 143,
        user: str = "",
        password: str = "",
        *,
        client: Any = None,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.client = client
        self.name = "imap"

    def read(self, query: dict[str, Any]) -> Observation:
        import imaplib

        owned = self.client is None
        client = self.client
        try:
            if client is None:
                client = imaplib.IMAP4(self.host, self.port)
                if self.user:
                    client.login(self.user, self.password)
            client.select("INBOX")
            typ, ids = client.search(None, "ALL")
            if typ != "OK":
                return Observation(self.name, False, "SEARCH failed", {})
            raw_ids = (ids[0] or b"").split()
            messages: list[Message] = []
            for item in raw_ids:
                fetched = client.fetch(item, "(RFC822)")
                if fetched[0] != "OK":
                    continue
                for part in fetched[1] or []:
                    if isinstance(part, tuple) and len(part) >= 2:
                        messages.append(message_from_bytes(part[1]))
            return _observation(self.name, messages, query)
        except (imaplib.IMAP4.error, OSError) as exc:
            return Observation(self.name, False, f"{type(exc).__name__}: {exc}", {})
        finally:
            if owned and client is not None:
                try:
                    client.logout()
                except (imaplib.IMAP4.error, OSError):
                    pass


def serve_imap(messages: list[bytes]) -> tuple[socket.socket, int]:
    """One-shot IMAP INBOX for tests. Speaks LOGIN, SELECT, SEARCH, FETCH, LOGOUT."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = int(sock.getsockname()[1])

    def session() -> None:
        try:
            conn, _addr = sock.accept()
        except OSError:
            return
        with conn:
            conn.sendall(b"* OK a3p imap\r\n")
            file = conn.makefile("rb")
            while True:
                line = file.readline()
                if not line:
                    break
                parts = line.decode("utf-8", "replace").strip().split(" ", 2)
                tag = parts[0]
                cmd = parts[1].upper() if len(parts) > 1 else ""
                if cmd == "FETCH":
                    number = int(parts[2].split()[0])
                    body = messages[number - 1]
                    conn.sendall(f"* {number} FETCH (RFC822 {{{len(body)}}}\r\n".encode())
                    conn.sendall(body + b")\r\n")
                    conn.sendall(f"{tag} OK FETCH completed\r\n".encode())
                elif cmd == "SEARCH":
                    ids = " ".join(str(index + 1) for index in range(len(messages)))
                    conn.sendall(f"* SEARCH {ids}\r\n{tag} OK SEARCH completed\r\n".encode())
                elif cmd == "LOGOUT":
                    conn.sendall(f"* BYE\r\n{tag} OK LOGOUT completed\r\n".encode())
                    break
                elif cmd == "SELECT":
                    conn.sendall(f"* {len(messages)} EXISTS\r\n{tag} OK SELECT completed\r\n".encode())
                elif cmd == "CAPABILITY":
                    conn.sendall(f"* CAPABILITY IMAP4rev1\r\n{tag} OK CAPABILITY completed\r\n".encode())
                else:
                    conn.sendall(f"{tag} OK {cmd} completed\r\n".encode())

    threading.Thread(target=session, daemon=True).start()
    return sock, port


class MailpitVerifier:
    """Read a Mailpit HTTP API. The probe does not send mail through this class."""

    def __init__(self, base_url: str, *, client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.name = "mailpit"

    def read(self, query: dict[str, Any]) -> Observation:
        try:
            response = self._get("/api/v1/messages")
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return Observation(self.name, False, f"{type(exc).__name__}: {exc}", {})
        if not isinstance(body, dict):
            return Observation(self.name, False, "message list was not an object", {})
        raw_messages = body.get("messages")
        summaries = raw_messages if isinstance(raw_messages, list) else []
        messages: list[Message] = []
        for item in summaries:
            if not isinstance(item, dict):
                continue
            message = Message()
            message["Subject"] = str(item.get("Subject") or "")
            to = item.get("To")
            if isinstance(to, list) and to and isinstance(to[0], dict):
                message["To"] = str(to[0].get("Address") or "")
            elif isinstance(to, str):
                message["To"] = to
            if query.get("body_contains"):
                message.set_payload(self._body(str(item.get("ID") or "")))
            messages.append(message)
        return _observation(self.name, messages, query)

    def _body(self, message_id: str) -> str:
        if not message_id:
            return ""
        try:
            response = self._get(f"/api/v1/message/{message_id}")
            body = response.json()
        except (httpx.HTTPError, ValueError):
            return ""
        if not isinstance(body, dict):
            return ""
        return str(body.get("Text") or "")

    def _get(self, path: str) -> httpx.Response:
        url = self.base_url + path
        if self.client is not None:
            response = self.client.get(url)
        else:
            response = httpx.get(url, timeout=20.0)
        response.raise_for_status()
        return response
