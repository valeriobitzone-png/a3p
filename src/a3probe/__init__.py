"""Deprecated import path. Use :mod:`a3p`."""

from __future__ import annotations

import warnings

from a3p import __version__

warnings.warn(
    "a3probe is deprecated and will be removed in the next version; use a3p",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["__version__"]
