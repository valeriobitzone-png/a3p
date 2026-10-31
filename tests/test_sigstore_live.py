"""Fulcio and Rekor round trip. Skips unless an ambient OIDC token exists.

GitHub Actions issues that token when the job sets permissions.id-token: write.
Set A3P_REQUIRE_SIGSTORE=1 to fail instead of skip, which is what that job does.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from a3p.attest import (
    canonical,
    sign_keyless,
    statement_for,
    verify_keyless,
    verify_keyless_cli,
)


def test_sigstore_keyless_round_trip(tmp_path: Path) -> None:
    from sigstore.oidc import detect_credential

    require = os.environ.get("A3P_REQUIRE_SIGSTORE") == "1"
    try:
        raw = detect_credential()
    except Exception as exc:
        if require:
            pytest.fail(f"id-token was required but was not issued: {exc}")
        pytest.skip(f"no ambient OIDC token: {exc}")
    if not raw:
        if require:
            pytest.fail("id-token was required but detect_credential returned nothing")
        pytest.skip("no ambient OIDC token")
    document = statement_for(
        "results.json",
        b"{}",
        {"statement": "assessed under A3P Method v1.0, level A3P-L0"},
    )
    bundle = sign_keyless(document)
    checked = verify_keyless(document, bundle, identity=bundle["identity"], issuer=bundle["issuer"])
    assert checked["logIndex"]
    assert checked["integratedTime"]
    artifact = tmp_path / "statement.json"
    bundle_path = tmp_path / "bundle.json"
    artifact.write_text(canonical(document), encoding="utf-8")
    bundle_path.write_text(json.dumps(bundle["bundle"]), encoding="utf-8")
    verify_keyless_cli(str(artifact), str(bundle_path), bundle["identity"], bundle["issuer"])
