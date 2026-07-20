from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.models.mission_state import AutonomyLevel, MissionState
from saber.models.scope import MissionScope
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


def test_recon_only_refuses_post_exploitation_canonical_spelling():
    """Regression: the canonical AssessmentPhase spelling 'post_exploitation' must
    be recognized as exploit-class, so recon_only refuses it rather than allowing it."""
    result = RiskGate().evaluate(
        _state(AutonomyLevel.RECON_ONLY),
        _action(RiskLevel.LOW, category="post_exploitation"),
    )
    assert result.decision == GateDecision.REFUSE


def test_out_of_scope_target_is_refused():
    """A target that is not in the mission scope is refused before any autonomy checks."""
    scope = MissionScope(
        mission_name="Scoped Assessment",
        targets=[Target(type=TargetType.IP, value="10.0.0.5")],
    )
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.99"),
        autonomy_level=AutonomyLevel.AUTONOMOUS,
        scope=scope,
    )
    result = RiskGate().evaluate(state, _action(RiskLevel.LOW))
    assert result.decision == GateDecision.REFUSE
