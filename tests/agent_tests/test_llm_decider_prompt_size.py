"""The decider prompt must stay affordable as the arsenal grows.

Workstream F gave 36 tools rich contracts, and the decider dumped the FULL catalog
JSON on every decision: ~122KB / ~30.6k tokens. That exceeded a provider per-request
prompt limit outright ("HTTP 402: Prompt tokens limit exceeded: 37223 > 30000"), so
missions failed on their first decision — and every step was slow, costly, and diluted
the small state summary with boilerplate.
"""

import json

from saber.core.tool_catalog import ToolCatalog
from saber.tools.registry import build_default_registry

# Chars, not tokens, so the test needs no tokenizer. ~4 chars/token, and the smallest
# provider limit seen in practice is 30k prompt tokens for the WHOLE request.
_MAX_CATALOG_CHARS = 60_000


def _catalog() -> ToolCatalog:
    return ToolCatalog.from_registry(build_default_registry())


def test_prompt_catalog_is_far_smaller_than_the_json_dump():
    catalog = _catalog()
    compact = len(catalog.to_prompt_text())
    verbose = len(json.dumps(catalog.to_dict(), indent=2, sort_keys=True, default=str))

    assert compact < verbose / 2, (
        f"compact rendering ({compact}) is not meaningfully smaller than the JSON dump "
        f"({verbose}); the prompt-size regression is back"
    )


def test_prompt_catalog_fits_a_conservative_request_budget():
    size = len(_catalog().to_prompt_text())
    assert size < _MAX_CATALOG_CHARS, (
        f"prompt catalog is {size} chars (~{size // 4} tokens). A 30k-token provider "
        f"limit applies to the WHOLE request, so this leaves no room for the state "
        f"summary. Trim tool/action descriptions or send a phase-filtered catalog."
    )


def test_the_decider_sends_the_compact_form_not_the_json_dump():
    """Structural guard: the regression was a single call to to_dict()."""

    import inspect

    from saber.agents.deciders.llm import LlmDecider

    source = inspect.getsource(LlmDecider._ask)
    assert "to_prompt_text()" in source
    assert "tool_catalog.to_dict()" not in source


def test_compact_form_still_names_every_tool_and_action():
    """Shrinking the prompt must not hide capability — that defeats the arsenal."""

    catalog = _catalog()
    text = catalog.to_prompt_text()

    for tool in catalog.tools:
        assert tool.name in text, f"{tool.name} missing from the prompt catalog"
        for action in tool.actions:
            assert action.action in text, f"{tool.name}.{action.action} missing"


def test_compact_form_keeps_required_args_visible():
    """The model must still know which args are mandatory, or it will be rejected."""

    catalog = _catalog()
    text = catalog.to_prompt_text()

    for tool in catalog.tools:
        for action in tool.actions:
            for arg in action.args:
                if arg.required:
                    assert arg.name in text, f"{tool.name}.{action.action} arg {arg.name} missing"


class _CapturingClient:
    """Captures the prompt instead of calling a model."""

    enabled = True

    def __init__(self) -> None:
        self.user_prompt = ""

    def __init__(self) -> None:
        self.user_prompt = ""
        self.system_prompt = ""

    def complete_json(self, *, system_prompt, user_prompt, metadata=None):
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        return {"kind": "stop", "rationale": "test"}


def _capture() -> _CapturingClient:
    """Run one decision against a capturing client and return it."""

    from saber.agents.deciders.llm import LlmDecider
    from saber.core.state_summary import StateSummarizer
    from saber.core.tool_catalog import ToolSpec
    from saber.models.mission_state import MissionState
    from saber.models.target import Target, TargetType

    client = _CapturingClient()
    catalog = ToolCatalog(
        [ToolSpec(name="nmap", category="recon", phase="recon", description="scan")]
    )
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        objective="Find a way in.",
    )
    LlmDecider(llm_client=client, tool_catalog=catalog).decide(
        state, StateSummarizer().summarize(state)
    )
    return client


def _capture_payload() -> str:
    """Return the per-call user payload."""

    return _capture().user_prompt


def test_the_payload_is_compact_json_not_pretty_printed():
    """indent=2 cost ~1,350 tokens per decision in whitespace alone.

    Measured on a 20-step mission state with a web-scoped catalog: 14% of a
    9,775-token prompt, paid again on every loop iteration.
    """

    prompt = _capture_payload()

    assert prompt, "no prompt was captured"
    assert "\n" not in prompt, "payload is pretty-printed; that is pure token waste"


def test_the_compact_payload_is_still_valid_json():
    """Compactness must not cost correctness."""

    payload = json.loads(_capture_payload())

    assert "summary" in payload
    assert "autonomy_level" in payload


def test_the_catalog_rides_in_the_cacheable_system_prefix_not_the_payload():
    """The catalog never changes during a mission, so it must not be re-sent per call.

    In the system prompt it sits in the cacheable prefix and bills at cache-read
    rates after the first decision. In the per-call payload it cost full input rate
    on ~3k tokens every single step.
    """

    client = _capture()

    assert "AVAILABLE TOOLS" in client.system_prompt
    assert "nmap" in client.system_prompt
    assert "tool_catalog" not in json.loads(client.user_prompt)
    assert "nmap" not in client.user_prompt


def test_the_payload_is_byte_stable_for_the_same_state():
    """Provider-side prompt caching needs an identical prefix across calls.

    sort_keys is what guarantees that, so it must not be dropped as redundant.
    """

    assert _capture_payload() == _capture_payload()
