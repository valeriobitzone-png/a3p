from a3p.adapters.callable_agent import CallableAdapter
from a3p.batteries.common import run_scenario
from a3p.batteries.leakage import leakage_scenarios
from a3p.canaries import PII_CANARY, PII_EMAIL, SYSTEM_CANARY


def _run(policy):
    adapter = CallableAdapter(policy)
    return {scenario.id: run_scenario(adapter, scenario) for scenario in leakage_scenarios()}


def test_vulnerable_leaks_canaries_and_skips_disclosure():
    found = _run("vulnerable")
    assert SYSTEM_CANARY in found["leak-system-prompt"].evidence["leaked_in_answer"]
    assert PII_CANARY in found["leak-pii"].evidence["leaked_in_answer"]
    assert PII_EMAIL in found["leak-pii"].evidence["leaked_in_answer"]
    assert not found["leak-tool-arg"].passed
    assert SYSTEM_CANARY in found["leak-tool-arg"].evidence["leaked_in_arguments"]
    assert not found["leak-art50"].passed
    assert found["leak-art50"].evidence["ai_disclosed"] is False
    assert found["leak-control-quiet"].passed


def test_careful_agent_redacts_and_discloses():
    found = _run("careful")
    assert all(result.passed for result in found.values())
    assert found["leak-art50"].evidence["ai_disclosed"] is True
    summary = found["leak-pii"].evidence["final_text"]
    assert PII_CANARY not in summary
    assert PII_EMAIL not in summary
