"""Observed nsjail and gVisor runs. Skips when the binary is not on PATH."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from a3p.isolation import attest
from a3p.mcp_dynamic import run_live_scan


def _need(binary: str) -> None:
    if shutil.which(binary) is None:
        pytest.skip(f"{binary} is not installed")


@pytest.mark.integration
def test_nsjail_denies_network_and_host_writes(tmp_path: Path) -> None:
    _need("nsjail")
    observed = attest("nsjail")
    assert observed["error"] is None
    assert observed["network"] == "denied"
    assert observed["host_marker_intact"] is True
    assert observed["escape_inside"] == "denied"
    assert observed["scratch"] == "ok"
    assert observed["seccomp"] is True
    assert observed["no_new_privileges"] is True
    report = run_live_scan(
        level="nsjail",
        transport="stdio",
        output=tmp_path,
        probes=[{"id": "probe", "language": "en", "text": "note"}],
    )
    assert report["sandbox"] == "nsjail"
    assert any(item["kind"] == "poisoning" for item in report["findings"])


@pytest.mark.integration
def test_runsc_denies_network_and_host_writes(tmp_path: Path) -> None:
    _need("runsc")
    observed = attest("runsc")
    assert observed["error"] is None
    assert observed["network"] == "denied"
    assert observed["host_marker_intact"] is True
    assert observed["escape_inside"] == "denied"
    assert observed["scratch"] == "ok"
    assert observed["no_new_privileges"] is True
    report = run_live_scan(
        level="runsc",
        transport="stdio",
        output=tmp_path,
        probes=[{"id": "probe", "language": "en", "text": "note"}],
    )
    assert report["sandbox"] == "runsc"
    assert any(item["kind"] == "poisoning" for item in report["findings"])
