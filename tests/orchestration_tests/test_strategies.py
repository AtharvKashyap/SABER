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


def test_web_objective_met_after_scan():
    from saber.models.mission_state import KnownTechnology, MissionState
    from saber.models.target import Target, TargetType
    from saber.orchestration.strategies.web import WebStrategy

    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.URL, value="http://x/"),
        technologies=[KnownTechnology(host="x", name="nginx")],
        metadata={"web_scanned": True},
    )
    assert WebStrategy().objective_met(state) is True


def test_ctf_objective_met_when_flag_found():
    from saber.models.mission_state import MissionState
    from saber.models.target import Target, TargetType
    from saber.orchestration.strategies.ctf import CtfStrategy

    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        metadata={"flag": "picoCTF{...}"},
    )
    assert CtfStrategy().objective_met(state) is True


def test_ctf_metadata_marks_lab():
    from saber.models.target import Target, TargetType
    from saber.orchestration.strategies.ctf import CtfStrategy

    meta = CtfStrategy().initial_metadata(Target(type=TargetType.IP, value="10.0.0.5"))
    assert meta["lab"] is True
