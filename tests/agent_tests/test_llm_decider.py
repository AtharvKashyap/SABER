import pytest
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.agents.deciders.llm import LlmDecider
from saber.core.state_summary import StateSummarizer
from saber.core.tool_catalog import ToolActionSpec, ToolCatalog, ToolSpec
from saber.models.mission_state import MissionState
from saber.models.target import Target, TargetType


class _FakeClient:
    def __init__(self, response):
        self._response = response
        self.enabled = True

    def complete_json(self, system_prompt, user_prompt, metadata=None):
        return self._response


def _catalog() -> ToolCatalog:
    return ToolCatalog(
        [
            ToolSpec(
                name="nmap",
                category="recon",
                phase="reconnaissance",
                description="scanner",
                actions=[
                    ToolActionSpec(tool_name="nmap", action="service_scan", description="scan")
                ],
            )
        ]
    )


def _state() -> MissionState:
    return MissionState(
        session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"), objective="assess"
    )


def test_valid_tool_decision_becomes_proposed_action():
    client = _FakeClient(
        {
            "kind": "tool",
            "tool_name": "nmap",
            "tool_action": "service_scan",
            "args": {"target": "10.0.0.5"},
            "agent_name": "recon_agent",
            "risk": "low",
            "category": "recon",
            "rationale": "start with recon",
        }
    )
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())
    action = decider.decide(_state(), StateSummarizer().summarize(_state()))
    assert action.kind == ActionKind.TOOL
    assert action.tool_name == "nmap"
    assert action.risk == RiskLevel.LOW
    assert action.metadata["category"] == "recon"


def test_unknown_tool_returns_stop():
    client = _FakeClient({"kind": "tool", "tool_name": "ghost", "tool_action": "x"})
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())
    action = decider.decide(_state(), StateSummarizer().summarize(_state()))
    assert action.kind == ActionKind.STOP


def test_report_decision():
    client = _FakeClient({"kind": "report", "rationale": "done"})
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())
    action = decider.decide(_state(), StateSummarizer().summarize(_state()))
    assert action.kind == ActionKind.REPORT


@pytest.mark.parametrize("bad_response", [[1, 2, 3], "done", 42, True, None])
def test_non_object_llm_response_returns_stop(bad_response):
    # A valid-but-non-object JSON response (list/scalar/null) must not crash the
    # mission loop; the decider must degrade to STOP instead of raising.
    client = _FakeClient(bad_response)
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())
    action = decider.decide(_state(), StateSummarizer().summarize(_state()))
    assert isinstance(action, ProposedAction)
    assert action.kind == ActionKind.STOP
