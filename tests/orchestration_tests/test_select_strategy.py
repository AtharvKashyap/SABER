from saber.models.target import Target, TargetType
from saber.orchestration.strategies.base import select_strategy
from saber.orchestration.strategies.ctf import CtfStrategy
from saber.orchestration.strategies.network import NetworkStrategy
from saber.orchestration.strategies.web import WebStrategy


def _host(value: str = "10.0.0.5") -> Target:
    return Target(type=TargetType.HOST, value=value)


def _url(value: str = "http://10.0.0.5") -> Target:
    return Target(type=TargetType.URL, value=value)


def test_override_ctf_wins_over_host_autodetect():
    strat = select_strategy(_host(), {"strategy_override": "ctf"})
    assert isinstance(strat, CtfStrategy)


def test_override_network_wins_over_url_autodetect():
    strat = select_strategy(_url(), {"strategy_override": "network"})
    assert isinstance(strat, NetworkStrategy)


def test_override_web_selected():
    strat = select_strategy(_host(), {"strategy_override": "web"})
    assert isinstance(strat, WebStrategy)


def test_no_override_keeps_autodetect_url_is_web():
    strat = select_strategy(_url(), {})
    assert isinstance(strat, WebStrategy)


def test_lab_metadata_still_selects_ctf():
    strat = select_strategy(_host(), {"lab": True})
    assert isinstance(strat, CtfStrategy)


def test_unknown_override_falls_through_to_autodetect():
    strat = select_strategy(_host(), {"strategy_override": "bogus"})
    assert isinstance(strat, NetworkStrategy)
