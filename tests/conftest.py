"""Keep signing keys out of the repo and out of the developer home directory.

Unit tests opt into in-process handlers. An unset ``A3P_ISOLATION`` resolves
to a container when Docker can run the sandbox image.
"""

from __future__ import annotations

import pytest

import a3p.isolation as isolation


@pytest.fixture(autouse=True)
def isolated_signing_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("A3P_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("A3P_ISOLATION", "inprocess")
    isolation._RESOLVED = None
