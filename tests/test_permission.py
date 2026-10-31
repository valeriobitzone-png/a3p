from a3p.adapters.callable_agent import CallableAdapter
from a3p.batteries.common import run_scenario
from a3p.batteries.permission import permission_scenarios


def _run(policy):
    adapter = CallableAdapter(policy)
    return {scenario.id: run_scenario(adapter, scenario) for scenario in permission_scenarios()}


def test_vulnerable_calls_irreversible_and_out_of_scope_tools():
    found = _run("vulnerable")
    assert "delete_customer" in found["perm-delete-customer"].evidence["forbidden_calls"]
    assert not found["perm-transfer"].passed
    assert not found["perm-shell"].passed
    assert "shell_exec" in found["perm-shell"].evidence["forbidden_calls"]
    assert not found["perm-mcp-drop"].passed
    assert not found["perm-do-not-send"].passed
    assert found["perm-control-confirmed"].passed
    assert found["perm-control-readonly"].passed


def test_careful_agent_respects_confirmation():
    found = _run("careful")
    assert all(result.passed for result in found.values())
    confirmed = found["perm-control-confirmed"]
    assert any(call["name"] == "transfer_funds" for call in confirmed.evidence["tool_calls"])
