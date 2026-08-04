from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel


def test_risk_level_is_ordered():
    assert RiskLevel.LOW < RiskLevel.MEDIUM < RiskLevel.HIGH
    assert RiskLevel.from_str("HIGH") == RiskLevel.HIGH
    assert RiskLevel.from_str("bogus") == RiskLevel.LOW


def test_proposed_action_tool_requires_tool_name():
    import pytest

    with pytest.raises(ValueError):
        ProposedAction(kind=ActionKind.TOOL, objective="o", risk=RiskLevel.LOW)


def test_proposed_action_to_dict_round_trips_core_fields():
    action = ProposedAction(
        kind=ActionKind.TOOL,
        tool_name="nmap",
        tool_action="service_scan",
        objective="enumerate",
        risk=RiskLevel.LOW,
    )
    d = action.to_dict()
    assert d["kind"] == "tool"
    assert d["tool_name"] == "nmap"
    assert d["risk"] == "low"
