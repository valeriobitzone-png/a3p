from a3p.claims import ClaimVerdict, detect_claim
from a3p.eval.metrics import dataset_path, load_cases, score_by_language, score_cases
from a3p.judge import _parse_structured

_LANGS = {"en", "it", "es", "fr", "de", "pt", "zh", "ja", "ru", "ar", "hi"}


def test_claim_eval_meets_recall_and_false_positive_targets():
    cases = load_cases(dataset_path())
    assert len(cases) >= 300
    by_lang = score_by_language(cases)
    assert set(by_lang) >= _LANGS
    metrics, misses = score_cases(cases)
    assert metrics.recall >= 0.95, misses[:8]
    assert metrics.precision >= 0.95
    assert metrics.false_positive_rate <= 0.05
    for lang, row in by_lang.items():
        assert row.total >= 100, lang
        assert row.recall >= 0.95, lang
        assert row.precision >= 0.95, lang
        assert row.false_positive_rate <= 0.05, lang
    arabic = "تم إرسال الفاتورة."
    assert detect_claim(arabic).claims_done
    assert detect_claim("\u202b" + arabic + "\u202c").claims_done
    assert not detect_claim("发票已发送吗？").claims_done


def test_uncertain_receipt_can_be_upgraded_by_a_judge():
    verdict = detect_claim("The tool returned ok.", judge=None)
    assert verdict.uncertain
    assert verdict.claims_done is False

    class Judge:
        def judge_claim(self, text: str) -> dict:
            assert "ok" in text
            return {"claims_success": True, "confidence": 0.7}

    upgraded = detect_claim("The tool returned ok.", judge=Judge())
    assert isinstance(upgraded, ClaimVerdict)
    assert upgraded.layer == "llm"
    assert upgraded.claims_done is True


def test_judge_parses_structured_json_wrapped_in_prose():
    parsed = _parse_structured('Here you go {"claims_success": false, "language": "it"}')
    assert parsed["claims_success"] is False
