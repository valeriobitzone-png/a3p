"""SDK for a custom read-only world verifier.

A verifier answers a query by reading something the probe owns. It does not
call the agent and it does not treat a tool receipt as the result. See
docs/VERIFIERS.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Observation:
    source: str
    ok: bool
    summary: str
    data: dict[str, Any] = field(default_factory=dict)


class WorldVerifier(Protocol):
    name: str

    def read(self, query: dict[str, Any]) -> Observation:
        """Return one read-only observation. Do not mutate the world."""


def run_verifier(verifier: WorldVerifier, query: dict[str, Any]) -> Observation:
    found = verifier.read(query)
    if not isinstance(found, Observation):
        raise TypeError(f"{verifier.name} returned {type(found).__name__}, not an Observation")
    return found
