"""Tests for target strategies and the strategy selector."""

from saber.models.mission_state import KnownVuln, MissionState
from saber.models.target import Target, TargetType
from saber.orchestration.strategies.base import StrategyKind, select_strategy


def test_url_selects_web_strategy():
    strat = select_strategy(Target(type=TargetType.URL, value="http://x/"))
    assert strat.kind == StrategyKind.WEB


def test_ip_selects_network_strategy():
    strat = select_strategy(Target(type=TargetType.IP, value="10.0.0.5"))
    assert strat.kind == StrategyKind.NETWORK


def test_ctf_flag_selects_ctf_strategy():
    strat = select_strategy(Target(type=TargetType.IP, value="10.0.0.5"), metadata={"ctf": True})
    assert strat.kind == StrategyKind.CTF


def test_network_objective_met_when_vulns_and_scanned():
    from saber.orchestration.strategies.network import NetworkStrategy

    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        vulns=[KnownVuln(title="v")],
        metadata={"exploit_intel_done": True},
    )
    assert NetworkStrategy().objective_met(state) is True
