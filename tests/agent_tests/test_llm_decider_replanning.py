"""The decider must not re-propose an action that already failed.

Repeating a failed action burns a mission step and, after
``StopEvaluator.max_repeat_failures``, ends the run. So a repeat is rejected once
and the model is re-asked with the offending signature called out.
"""

from saber.agents.deciders.base import ActionKind
from saber.agents.deciders.llm import LlmDecider
from saber.core.state_summary import StateSummarizer
from saber.core.tool_catalog import ToolActionSpec, ToolCatalog, ToolSpec
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.target import Target, TargetType
from saber.tools.contract import ArgSpec


class _FakeClient:
    """LLM stub that returns a scripted sequence of decisions."""

    enabled = True

    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts: list[str] = []

    def complete_json(self, system_prompt, user_prompt, metadata=None):
        self.prompts.append(user_prompt)
        return self.responses.pop(0) if self.responses else self.responses_exhausted()

    @staticmethod
    def responses_exhausted():
        raise AssertionError("decider asked more times than the test scripted")


def _catalog():
    actions = [
        ToolActionSpec(
            tool_name="nmap",
            action="service_scan",
            description="d",
            args=(ArgSpec("ports", "str", required=False),),
        ),
        ToolActionSpec(
            tool_name="nmap",
            action="udp_scan",
            description="d",
            args=(ArgSpec("ports", "str", required=False),),
        ),
    ]
    return ToolCatalog(
        [ToolSpec(name="nmap", category="recon", phase="recon", description="d", actions=actions)]
    )


def _state(failed: list[AttemptedAction] | None = None) -> MissionState:
    state = MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"))
    if failed:
        return state.model_copy(update={"attempted_actions": failed})
    return state


def _decision(action: str, ports: str | None = None):
    args = {"ports": ports} if ports is not None else {}
    return {
        "kind": "tool",
        "tool_name": "nmap",
        "tool_action": action,
        "args": args,
        "rationale": f"run {action}",
    }


def _failed(action: str, ports: str | None = None) -> AttemptedAction:
    args = {"ports": ports} if ports is not None else {}
    return AttemptedAction(tool_name="nmap", action=action, args=args, success=False, reason="boom")


def _summary(state):
    return StateSummarizer().summarize(state)


def test_failed_signatures_exposed_on_state():
    state = _state([_failed("service_scan", "80")])
    signatures = state.failed_signatures
    assert len(signatures) == 1
    assert "nmap:service_scan" in next(iter(signatures))


def test_a_fresh_proposal_is_returned_untouched():
    client = _FakeClient([_decision("service_scan", "80")])
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())

    action = decider.decide(_state(), _summary(_state()))

    assert action.kind == ActionKind.TOOL
    assert action.tool_action == "service_scan"
    assert len(client.prompts) == 1, "no retry should happen when nothing failed"


def test_repeat_of_a_failed_action_triggers_one_retry():
    state = _state([_failed("service_scan", "80")])
    client = _FakeClient([_decision("service_scan", "80"), _decision("udp_scan", "53")])
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())

    action = decider.decide(state, _summary(state))

    assert len(client.prompts) == 2, "the repeat should have been rejected and re-asked"
    assert action.tool_action == "udp_scan"
    assert "repeated_failed_signature" not in action.metadata


def test_retry_prompt_names_the_rejected_action():
    state = _state([_failed("service_scan", "80")])
    client = _FakeClient([_decision("service_scan", "80"), _decision("udp_scan")])
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())

    decider.decide(state, _summary(state))

    retry_prompt = client.prompts[1]
    assert "rejected_action" in retry_prompt
    assert "already failed" in retry_prompt
    assert "service_scan" in retry_prompt


def test_an_insistent_model_is_flagged_but_not_stopped():
    """The repeat guard is the loop's job; the decider must not end the mission."""

    state = _state([_failed("service_scan", "80")])
    client = _FakeClient([_decision("service_scan", "80"), _decision("service_scan", "80")])
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())

    action = decider.decide(state, _summary(state))

    assert action.kind == ActionKind.TOOL, "must not be turned into a STOP"
    assert action.metadata.get("repeated_failed_signature") is True


def test_different_args_are_not_treated_as_a_repeat():
    """Varying the args is exactly the replanning we want to allow."""

    state = _state([_failed("service_scan", "80")])
    client = _FakeClient([_decision("service_scan", "1-65535")])
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())

    action = decider.decide(state, _summary(state))

    assert len(client.prompts) == 1
    assert action.args == {"ports": "1-65535"}


def test_a_successful_action_is_not_in_the_avoid_set():
    succeeded = AttemptedAction(
        tool_name="nmap", action="service_scan", args={"ports": "80"}, success=True
    )
    state = _state([succeeded])
    client = _FakeClient([_decision("service_scan", "80")])
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())

    action = decider.decide(state, _summary(state))

    assert len(client.prompts) == 1, "only FAILED actions should be avoided"
    assert action.tool_action == "service_scan"


def test_summary_exposes_failed_args_and_signature_to_the_model():
    state = _state([_failed("service_scan", "80")])
    payload = _summary(state).to_dict()

    failure = payload["recent_failures"][0]
    assert failure["args"] == {"ports": "80"}
    assert "signature" in failure
    assert payload["current_phase"] == "recon"
