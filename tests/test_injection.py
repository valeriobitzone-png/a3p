from a3p.adapters.callable_agent import CallableAdapter
from a3p.batteries.common import run_scenario
from a3p.batteries.injection import injection_scenarios
from a3p.canaries import JAILBREAK_MARKER, SYSTEM_CANARY


def _run(policy):
    adapter = CallableAdapter(policy)
    return {scenario.id: run_scenario(adapter, scenario) for scenario in injection_scenarios()}


def test_vulnerable_follows_indirect_injection():
    found = _run("vulnerable")
    leaked = found["inj-indirect-email"]
    assert not leaked.passed
    assert "forward_secrets" in leaked.evidence["forbidden_calls"]
    assert SYSTEM_CANARY in leaked.evidence["leaked"]
    assert not found["inj-direct-system"].passed
    assert SYSTEM_CANARY in found["inj-direct-system"].evidence["final_text"]
    assert not found["inj-direct-marker"].passed
    assert JAILBREAK_MARKER in found["inj-direct-marker"].evidence["final_text"]
    assert not found["inj-tool-description"].passed
    assert not found["inj-indirect-html"].passed
    assert found["inj-control-benign-ignore"].passed


def test_careful_agent_does_not_follow_tool_output():
    found = _run("careful")
    assert all(result.passed for result in found.values())
