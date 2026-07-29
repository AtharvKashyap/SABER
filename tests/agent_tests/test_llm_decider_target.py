"""The decider may aim an action at a specific discovered host (pivoting).

`ActionExecutor` uses `action.target or state.target`, and `RiskGate` scope-checks
`action.target`, so the only missing piece was `LlmDecider` populating it.
"""

from saber.agents.deciders.base import ActionKind
from saber.agents.deciders.llm import LlmDecider
from saber.core.tool_catalog import ToolActionSpec, ToolCatalog, ToolSpec
from saber.models.target import TargetType
from saber.tools.contract import ArgSpec


def _decider():
    action = ToolActionSpec(
        tool_name="nmap", action="service_scan", description="d",
        args=(ArgSpec("ports", "str", required=False),),
    )
    catalog = ToolCatalog([ToolSpec(name="nmap", category="recon", phase="recon",
                                    description="d", actions=[action])])
    return LlmDecider(llm_client=None, tool_catalog=catalog)


def _raw(**overrides):
    raw = {
        "kind": "tool",
        "tool_name": "nmap",
        "tool_action": "service_scan",
        "args": {},
        "rationale": "scan the newly discovered host",
    }
    raw.update(overrides)
    return raw


def test_target_omitted_leaves_action_target_none():
    action = _decider()._parse(_raw())
    assert action.kind == ActionKind.TOOL
    assert action.target is None


def test_discovered_ip_becomes_action_target():
    action = _decider()._parse(_raw(target="192.168.56.102"))
    assert action.target is not None
    assert action.target.value == "192.168.56.102"
    assert action.target.type == TargetType.IP


def test_url_target_is_typed_as_url():
    action = _decider()._parse(_raw(target="http://192.168.56.101:8080/admin"))
    assert action.target.type == TargetType.URL


def test_cidr_target_is_typed_as_cidr():
    action = _decider()._parse(_raw(target="192.168.56.0/24"))
    assert action.target.type == TargetType.CIDR


def test_domain_target_is_typed_as_domain():
    action = _decider()._parse(_raw(target="dev.example.com"))
    assert action.target.type == TargetType.DOMAIN


def test_unparseable_target_falls_back_rather_than_crashing():
    for bad in ("", "   ", None, 42, {"host": "x"}, "!!! not a target !!!"):
        action = _decider()._parse(_raw(target=bad))
        # Still a usable TOOL action; executor falls back to state.target.
        assert action.kind == ActionKind.TOOL
        assert action.target is None
