"""Stdlib progress lines for ``a3p scan``. No extra dependency."""

from __future__ import annotations

from typing import TextIO

from a3p.models import ScenarioResult


class LiveProgress:
    def __init__(self, total: int, stream: TextIO) -> None:
        self.total = max(total, 1)
        self.done = 0
        self.failed = 0
        self.stream = stream
        self.tty = bool(getattr(stream, "isatty", lambda: False)())

    def __call__(self, result: ScenarioResult) -> None:
        self.done += 1
        if not result.passed:
            self.failed += 1
        mark = "pass" if result.passed else "FAIL"
        line = (
            f"[{self.done:>3}/{self.total}] {mark:<4} "
            f"{result.battery}/{result.scenario_id}  failed {self.failed}"
        )
        if self.tty:
            self.stream.write("\r" + line + " " * 8)
            self.stream.flush()
        else:
            self.stream.write(line + "\n")
            self.stream.flush()

    def close(self) -> None:
        if self.tty:
            self.stream.write("\n")
            self.stream.flush()
