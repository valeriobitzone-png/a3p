"""Deprecated console entry. Use ``a3p``."""

from __future__ import annotations

import warnings


def main(argv: list[str] | None = None) -> int:
    warnings.warn(
        "a3probe is deprecated and will be removed in the next version; use a3p",
        DeprecationWarning,
        stacklevel=2,
    )
    from a3p.cli import main as current

    return current(argv)
