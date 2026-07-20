from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.models.mission_state import AutonomyLevel, MissionState
from saber.models.target import Target, TargetType
from saber.orchestration.risk_gate import GateDecision, RiskGate


def _state(level: AutonomyLevel) -> MissionState:
    return MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        autonomy_level=level,
    )


def _action(
    risk: RiskLevel, category: str = "recon", requires_confirmation: bool = False
) -> ProposedAction:
    return ProposedAction(
        kind=ActionKind.TOOL,
        tool_name="t",
        tool_action="a",
        objective="o",
        risk=risk,
        requires_confirmation=requires_confirmation,
        metadata={"category": category},
    )


def test_autonomous_allows_low_and_medium():
    gate = RiskGate()
    assert (
        gate.evaluate(_state(AutonomyLevel.AUTONOMOUS), _action(RiskLevel.LOW)).decision
        == GateDecision.ALLOW
    )
    assert (
        gate.evaluate(_state(AutonomyLevel.AUTONOMOUS), _action(RiskLevel.MEDIUM)).decision
        == GateDecision.ALLOW
    )


def test_autonomous_confirms_high_risk():
    result = RiskGate().evaluate(
        _state(AutonomyLevel.AUTONOMOUS), _action(RiskLevel.HIGH, category="exploitation")
    )
    assert result.decision == GateDecision.CONFIRM


def test_assisted_confirms_exploit_class_even_at_low_risk():
    result = RiskGate().evaluate(
        _state(AutonomyLevel.ASSISTED), _action(RiskLevel.LOW, category="exploitation")
    )
    assert result.decision == GateDecision.CONFIRM


def test_recon_only_refuses_exploit_class():
    result = RiskGate().evaluate(
        _state(AutonomyLevel.RECON_ONLY), _action(RiskLevel.LOW, category="post_exploit")
    )
    assert result.decision == GateDecision.REFUSE
