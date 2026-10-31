"""Read-only SQL. SQLite is built in. Postgres is any DB-API connection."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from a3p.world.base import Observation

_READ = re.compile(r"^\s*(select|with)\b", re.IGNORECASE)
_WRITE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|attach|detach|pragma|grant|revoke|copy|call)\b",
    re.IGNORECASE,
)


def read_only_reason(sql: str) -> str | None:
    body = sql.strip()
    if body.endswith(";"):
        body = body[:-1].rstrip()
    if not body:
        return "empty SQL"
    if ";" in body:
        return "only one statement is allowed"
    if not _READ.match(body):
        return "only a SELECT statement is allowed"
    if _WRITE.search(body):
        return "statement is not read-only"
    return None


def _rows(connection: Any, sql: str, params: list[Any] | tuple[Any, ...]) -> list[Any]:
    cursor = connection.cursor()
    cursor.execute(sql, params)
    found = cursor.fetchall()
    return list(found)


class SqlVerifier:
    """Read a DB-API connection. The caller owns the connection."""

    def __init__(self, connection: Any, *, dialect: str = "dbapi") -> None:
        self.connection = connection
        self.dialect = dialect
        self.name = f"sql:{dialect}"

    def read(self, query: dict[str, Any]) -> Observation:
        sql = str(query.get("sql") or "")
        reason = read_only_reason(sql)
        if reason:
            return Observation(self.name, False, reason, {"sql": sql})
        params = query.get("params") or ()
        if not isinstance(params, (list, tuple)):
            return Observation(self.name, False, "params must be a list", {})
        try:
            rows = _rows(self.connection, sql.strip().rstrip(";"), tuple(params))
        except Exception as exc:
            return Observation(self.name, False, f"{type(exc).__name__}: {exc}", {})
        expect = query.get("expect_rows")
        ok = True if expect is None else len(rows) == int(expect)
        summary = f"{len(rows)} rows"
        if not ok:
            summary = f"{len(rows)} rows, expected {expect}"
        return Observation(self.name, ok, summary, {"rows": rows[:50], "count": len(rows)})


class SqliteVerifier(SqlVerifier):
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        super().__init__(None, dialect="sqlite")
        self.name = "sql:sqlite"

    def read(self, query: dict[str, Any]) -> Observation:
        with sqlite3.connect(self.path) as connection:
            self.connection = connection
            return super().read(query)


class PostgresVerifier(SqlVerifier):
    def __init__(self, connection: Any) -> None:
        super().__init__(connection, dialect="postgres")
        self.name = "sql:postgres"


def connect_postgres(dsn: str) -> Any:
    """Open a Postgres connection. ``psycopg`` is the optional ``world`` extra."""
    try:
        import psycopg
    except ImportError:
        pass
    else:
        return psycopg.connect(dsn)
    try:
        import psycopg2
    except ImportError as exc:
        raise RuntimeError(
            "PostgresVerifier needs the world extra (psycopg) or psycopg2. "
            "Neither is installed. Pass an already open DB-API connection instead."
        ) from exc
    return psycopg2.connect(dsn)
