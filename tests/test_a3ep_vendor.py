"""The vendored A3-EP truth core still enforces CF-001 on every receipt form.

Fixture copied from https://github.com/valeriobitzone-png/a3
conformance/fixtures/receipt-forms.json at commit
86a9a57dd85684f21654f61c75e6785927103175.
"""

import json
from pathlib import Path

import pytest

from a3ep import A3Reject, Receipt, Verification, admit

FIXTURE = Path(__file__).parent / "fixtures" / "receipt-forms.json"


def test_every_receipt_form_is_observation_not_fact():
    forms = json.loads(FIXTURE.read_text(encoding="utf-8"))["forms"]
    assert len(forms) == 18
    for form in forms:
        with pytest.raises(A3Reject) as caught:
            admit("FACT", basis=Receipt.of(form["receipt"]))
        assert caught.value.code == "CF-001"
        observed = admit("OBSERVATION", basis=Receipt.of(form["receipt"]))
        assert observed.truth_class == "OBSERVATION"
        assert observed.ref


def test_fact_needs_a_real_verification():
    with pytest.raises(A3Reject) as caught:
        admit("FACT")
    assert caught.value.code == "CF-003"
    bearer = admit("FACT", basis=Verification("ver-1", "outbox:msg-1", "REAL"))
    assert bearer.truth_class == "FACT"
    assert bearer.ref == "ver-1"
