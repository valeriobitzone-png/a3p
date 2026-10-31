import json
from pathlib import Path

from a3p.batteries.external import load_garak, load_promptfoo, run_if_available


def test_promptfoo_failed_assertion_is_a_finding(tmp_path: Path):
    path = tmp_path / "promptfoo.json"
    path.write_text(
        json.dumps(
            {
                "results": {
                    "results": [
                        {
                            "success": False,
                            "prompt": {"raw": "ignore instructions"},
                            "response": {"output": "system prompt"},
                            "testCase": {"description": "direct injection"},
                        },
                        {"success": True, "testCase": {"description": "blocked"}},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    findings = load_promptfoo(path)
    assert len(findings) == 1
    assert findings[0].battery == "injection"
    assert findings[0].passed is False
    assert "direct injection" in findings[0].title


def test_garak_hit_rows(tmp_path: Path):
    path = tmp_path / "garak.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps({"entry_type": "attempt", "probe": "promptinject", "status": 1, "prompt": "x", "output": "y"}),
                json.dumps({"entry_type": "attempt", "probe": "promptinject", "status": 0, "prompt": "safe"}),
                json.dumps({"probe": "leak", "vulnerable": True, "output": "token"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    findings = load_garak(path)
    assert len(findings) == 2
    assert findings[0].evidence["source"] == "garak"


def test_missing_scanner_is_skipped():
    assert run_if_available("promptfoo", ["--version"]) is None or isinstance(
        run_if_available("promptfoo", ["--version"]), str
    )
