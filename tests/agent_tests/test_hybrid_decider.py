"""The hybrid decider must save tokens without ever deciding for the model.

Its whole justification is that some steps are not decisions: with no services
known, the only sensible action is to look, and paying ~8k prompt tokens for a
model to say so buys nothing. The danger is the obvious one — a "cheap path" that
quietly takes over choices where more than one action is defensible. These tests
pin the boundary in both directions.
"""

from __future__ import annotations

from saber.agents.deciders.base import ActionKind, NextActionDecider, ProposedAction
from saber.agents.deciders.hybrid import HybridDecider
from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import (
    AttemptedAction,
    KnownService,
    KnownTechnology,
    KnownVuln,
    MissionState,
)
from saber.models.target import Target, TargetType


class _RecordingLlm(NextActionDecider):
    """Stands in for the model, recording whether it was consulted."""

    def __init__(self) -> None:
        self.calls = 0

    def decide(self, state, summary) -> ProposedAction:
        self.calls += 1
        return ProposedAction(
            kind=ActionKind.TOOL,
            tool_name="sqlmap",
            tool_action="test_injection",
            args={"url": "http://10.0.0.5/x"},
            objective="model choice",
        )


def _state(**kwargs) -> MissionState:
    base = {
        "session_id": "s",
        "target": Target(type=TargetType.IP, value="10.0.0.5"),
        "objective": "Get in.",
    }
    return MissionState(**{**base, **kwargs})


def _decide(state):
    llm = _RecordingLlm()
    action = HybridDecider(llm_decider=llm).decide(state, StateSummarizer().summarize(state))
    return action, llm


# ------------------------------------------------------------------ forced moves


def test_an_empty_state_does_not_consult_the_model() -> None:
    """Nothing is known, so anything but looking would be guessing."""

    action, llm = _decide(_state())

    assert llm.calls == 0
    assert (action.tool_name, action.tool_action) == ("nmap", "service_scan")
    assert action.metadata["decided_by"] == "deterministic"
    assert action.metadata["forced"] is True


def test_an_unfingerprinted_web_port_does_not_consult_the_model() -> None:
    action, llm = _decide(
        _state(services=[KnownService(host="10.0.0.5", port=80, protocol="tcp", state="open")])
    )

    assert llm.calls == 0
    assert action.tool_name == "whatweb"
    assert action.metadata["forced"] is True


# --------------------------------------------------------------- real decisions


def test_once_the_stack_is_known_the_model_decides() -> None:
    """Which scanner, which exploit, whether to pivot — all genuine judgement."""

    action, llm = _decide(
        _state(
            services=[KnownService(host="10.0.0.5", port=80, protocol="tcp", state="open")],
            technologies=[KnownTechnology(host="10.0.0.5", name="Apache", version="2.4.41")],
        )
    )

    assert llm.calls == 1
    assert action.tool_name == "sqlmap"
    assert action.metadata["decided_by"] == "llm"


def test_a_non_web_service_is_not_treated_as_forced() -> None:
    """An open SSH port has many reasonable next moves, so the model must choose."""

    action, llm = _decide(
        _state(services=[KnownService(host="10.0.0.5", port=22, protocol="tcp", state="open")])
    )

    assert llm.calls == 1
    assert action.metadata["decided_by"] == "llm"


def test_a_rich_mid_mission_state_always_reaches_the_model() -> None:
    state = _state(
        services=[
            KnownService(host="10.0.0.5", port=p, protocol="tcp", state="open")
            for p in (22, 80, 443, 3306)
        ],
        technologies=[KnownTechnology(host="10.0.0.5", name="PHP", version="7.4")],
        vulns=[KnownVuln(host="10.0.0.5", title="SQLi", severity="critical")],
        attempted_actions=[
            AttemptedAction(tool_name="nmap", action="service_scan", success=True),
            AttemptedAction(tool_name="whatweb", action="fingerprint", success=True),
        ],
    )

    _, llm = _decide(state)

    assert llm.calls == 1


def test_the_ladder_never_overrides_a_model_decision() -> None:
    """The delegation is one-directional: forced -> ladder, otherwise -> model.

    If the ladder could veto the model, token savings would start costing reasoning.
    """

    state = _state(
        services=[KnownService(host="10.0.0.5", port=80, protocol="tcp", state="open")],
        technologies=[KnownTechnology(host="10.0.0.5", name="Apache")],
    )
    action, llm = _decide(state)

    assert llm.calls == 1
    assert action.tool_name == "sqlmap", "the ladder overrode a genuine model decision"


def test_a_forced_state_with_an_exhausted_ladder_falls_through_to_the_model() -> None:
    """A mission must not die because the ladder has nothing left to say.

    Services are empty (forced), but nmap was already attempted, so the ladder
    declines. The model has to get the question rather than the loop stopping.
    """

    state = _state(
        attempted_actions=[AttemptedAction(tool_name="nmap", action="service_scan", success=False)]
    )
    action, llm = _decide(state)

    assert llm.calls == 1
    assert action.metadata["decided_by"] == "llm"


def test_every_decision_records_who_made_it() -> None:
    """The operator needs to see which steps were reasoned and which were forced."""

    forced, _ = _decide(_state())
    reasoned, _ = _decide(
        _state(
            services=[KnownService(host="10.0.0.5", port=22, protocol="tcp", state="open")],
        )
    )

    assert forced.metadata["decided_by"] == "deterministic"
    assert reasoned.metadata["decided_by"] == "llm"
