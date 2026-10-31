from a3p.adapters.callable_agent import CallableAdapter
from a3p.models import Mapping, ScenarioResult
from a3p.report_html import render_html
from a3p.report_pdf import render_pdf
from a3p.runner import write_run
from a3p.scoring import band, battery_score, overall_score


def _result(passed: bool, severity: str = "high") -> ScenarioResult:
    return ScenarioResult(
        scenario_id="s",
        battery="phantom",
        title="t",
        passed=passed,
        fail_severity=severity,
        summary="summary",
        remediation="fix",
        reproduction=["step"],
        mappings=[Mapping("a3ep", "CF-001", "A tool receipt is not a FACT")],
        evidence={},
    )


def test_score_math():
    assert battery_score([_result(True), _result(True)]) == 100
    assert battery_score([_result(False, "critical")]) == 0
    mixed = [_result(True, "high"), _result(False, "high")]
    assert battery_score(mixed) == 50
    assert overall_score({"phantom": 50, "injection": 100}) == 75
    assert band(96, [_result(False, "high")]) == "review"
    assert band(10, [_result(False, "critical")]) == "fail"
    assert band(100, [_result(True)]) == "pass"


def test_html_and_pdf_from_a_run(tmp_path):
    report = write_run(
        CallableAdapter("vulnerable"),
        tmp_path,
        {
            "client": "Northwind Demo (fictional)",
            "agent_name": "callable vulnerable",
            "agent_version": "test",
            "scope": "unit",
            "auditor": "test",
        },
    )
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    pdf = (tmp_path / "report.pdf").read_bytes()
    assert report["band"] == "fail"
    assert report["meta"]["assurance_level"] == "A3P-L1"
    assert report["meta"]["assessment"] == "assessed under A3P Method v1.0, level A3P-L1"
    assert "guaranteed safe" not in report["meta"]["assessment"].lower()
    assert "Tools" in html and "inprocess" in html
    assert (tmp_path / "badge.json").is_file()
    assert (tmp_path / "badge.svg").is_file()
    assert (tmp_path / "repro.json").is_file()
    assert "not a certification" in html
    assert "CF-001" in html
    assert "Article 50" in html or "art. 50" in html
    assert "LLM01" in html
    assert "ASI01" in html
    assert "sample-based" in html.lower() or "Sample-based" in html
    assert pdf.startswith(b"%PDF")
    assert (tmp_path / "ledger.jsonl").is_file()
    again = render_html(report)
    assert "A3 Score" in again
    render_pdf(report, tmp_path / "again.pdf")
    assert (tmp_path / "again.pdf").stat().st_size > 1000
