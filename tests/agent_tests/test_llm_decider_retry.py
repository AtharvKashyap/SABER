"""A transient model failure must not destroy the whole mission.

`MissionLoop` turns a decider ERROR into MissionRunStatus.FAILED, so a single 429
mid-run used to kill an otherwise-healthy engagement. Observed live: two missions
that each passed individually both failed when the suite ran them back-to-back and
the provider rate-limited one call.
"""

from saber.agents.deciders.base import ActionKind
from saber.agents.deciders.llm import LlmDecider
from saber.core.state_summary import StateSummarizer
from saber.core.tool_catalog import ToolActionSpec, ToolCatalog, ToolSpec
from saber.models.mission_state import MissionState
from saber.models.target import Target, TargetType
from saber.tools.contract import ArgSpec


class _FlakyClient:
    """Raises a scripted sequence of errors, then succeeds."""

    enabled = True

    def __init__(self, errors):
        self.errors = list(errors)
        self.calls = 0

    def complete_json(self, system_prompt, user_prompt, metadata=None):
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return {
            "kind": "tool",
            "tool_name": "nmap",
            "tool_action": "service_scan",
            "args": {},
            "rationale": "scan",
        }


def _catalog():
    action = ToolActionSpec(
        tool_name="nmap", action="service_scan", description="d",
        args=(ArgSpec("ports", "str", required=False),),
    )
    return ToolCatalog(
        [ToolSpec(name="nmap", category="recon", phase="recon", description="d", actions=[action])]
    )


def _decide(client):
    decider = LlmDecider(
        llm_client=client, tool_catalog=_catalog(), retry_backoff_seconds=0.0
    )
    state = MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"))
    return decider.decide(state, StateSummarizer().summarize(state))


def test_rate_limit_is_retried_and_the_mission_continues():
    client = _FlakyClient([RuntimeError("HTTP 429 Too Many Requests")])
    action = _decide(client)

    assert action.kind == ActionKind.TOOL, "a retryable 429 must not fail the mission"
    assert client.calls == 2


def test_transient_5xx_and_timeouts_are_retried():
    for error in (
        RuntimeError("503 Service Unavailable"),
        TimeoutError("request timed out"),
        RuntimeError("upstream connection reset"),
    ):
        client = _FlakyClient([error])
        assert _decide(client).kind == ActionKind.TOOL, error


def test_retries_are_bounded_and_then_report_error():
    client = _FlakyClient([RuntimeError("429 rate limit")] * 5)
    action = _decide(client)

    assert action.kind == ActionKind.ERROR
    assert client.calls == 3, "must stop at max_attempts rather than retry forever"


def test_a_permanent_error_is_not_retried():
    """An auth or malformed-request failure will not fix itself; retrying wastes time."""

    client = _FlakyClient([RuntimeError("401 Unauthorized: invalid api key")])
    action = _decide(client)

    assert action.kind == ActionKind.ERROR
    assert client.calls == 1


def test_no_retry_when_the_first_call_succeeds():
    client = _FlakyClient([])
    assert _decide(client).kind == ActionKind.TOOL
    assert client.calls == 1
