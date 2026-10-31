"""Environment variables. ``A3P_*`` wins; ``A3PROBE_*`` remains for one version."""

from __future__ import annotations

import os


def setting(name: str) -> str | None:
    """Return ``A3P_NAME`` when it is set, including an empty string.

    Otherwise return ``A3PROBE_NAME`` when that is set. Missing names return None.
    """
    primary = f"A3P_{name}"
    if primary in os.environ:
        return os.environ[primary]
    legacy = f"A3PROBE_{name}"
    if legacy in os.environ:
        return os.environ[legacy]
    return None
