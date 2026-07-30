"""An exploit attempt must be legible to the decider — success AND failure.

A failed attempt that yields "crashed with SIGSEGV" or "leaked 0x7ffd..." is what
lets the next iteration be better. A parser that only noticed flags would make the
loop blind between attempts.
"""

from pathlib import Path

from saber.parsers.pwntools import PwntoolsParser

from tests.conftest import assert_observation, merge_observations

_WIN = Path("tests/fixtures/sample_pwntools_output.txt")
_CRASH = Path("tests/fixtures/sample_pwntools_crash_output.txt")
_META = {"binary_path": "/opt/lab/vulnbin", "target": "10.0.0.5"}


def _observations(fixture: Path, metadata=_META):
    result = PwntoolsParser().parse_text(fixture.read_text(), metadata=metadata)
    return result, [o.to_dict() for o in result.observations]


def test_emits_only_canonical_kinds():
    from saber.core.canonical_kinds import CANONICAL_KINDS

    for fixture in (_WIN, _CRASH):
        _, obs = _observations(fixture)
        assert obs
        assert {o["kind"] for o in obs} <= CANONICAL_KINDS


def test_successful_exploit_yields_a_flag():
    _, obs = _observations(_WIN)
    flags = [o for o in obs if o["kind"] == "flag"]

    assert len(flags) == 1
    assert_observation(
        flags[0],
        kind="flag",
        data_subset={
            "value": "flag{f4ke_l4b_r3t2w1n_fl4g}",
            "location": "/opt/lab/vulnbin",
            "host": "10.0.0.5",
        },
    )


def test_leaked_address_is_reported_for_the_next_attempt():
    _, obs = _observations(_WIN)
    leak = next(o for o in obs if o["data"].get("metadata", {}).get("outcome") == "leak")

    assert leak["data"]["metadata"]["address"] == "0x7ffd1a2b3c40"
    assert leak["data"]["severity"] == "high"


def test_crash_is_recorded_as_progress_not_silence():
    """A segfault means the input reached the instruction pointer."""

    _, obs = _observations(_CRASH)
    crash = next(o for o in obs if o["data"].get("metadata", {}).get("outcome") == "crash")

    assert crash["data"]["metadata"]["signal"] == "SIGSEGV"
    assert crash["data"]["severity"] == "high"
    assert "instruction pointer" in crash["data"]["detail"]


def test_eof_is_reported_so_the_offset_can_be_revised():
    _, obs = _observations(_CRASH)
    outcomes = {o["data"].get("metadata", {}).get("outcome") for o in obs}
    assert "eof" in outcomes


def test_a_failed_attempt_still_grows_state():
    """Otherwise the decider has nothing to reason about between iterations."""

    _, obs = _observations(_CRASH)
    state = merge_observations(obs, tool="pwntools", action="run_exploit")

    assert state.flags == []
    assert state.notes, "a failed attempt must still record what happened"


def test_flag_capture_grows_state_flags():
    _, obs = _observations(_WIN)
    state = merge_observations(obs, tool="pwntools", action="run_exploit")

    assert len(state.flags) == 1
    assert state.flags[0].value == "flag{f4ke_l4b_r3t2w1n_fl4g}"
    assert state.flags[0].location == "/opt/lab/vulnbin"


def test_script_traceback_is_distinguished_from_a_failed_exploit():
    """A broken script is a different problem from a wrong payload."""

    text = (
        "Traceback (most recent call last):\n"
        '  File "/workspace/tmp/exploit.py", line 4, in <module>\n'
        "    p.sendline(payload)\n"
        "NameError: name 'payload' is not defined\n"
    )
    result = PwntoolsParser().parse_text(text, metadata=_META)
    outcomes = {o.data["metadata"]["outcome"] for o in result.observations}

    assert outcomes == {"script_error"}
    assert result.observations[0].data["severity"] == "high"


def test_stack_canary_is_called_out_as_a_different_strategy():
    text = "*** stack smashing detected ***: terminated\n"
    result = PwntoolsParser().parse_text(text, metadata=_META)
    note = result.observations[0].to_dict()

    assert note["data"]["metadata"]["outcome"] == "canary"
    assert "leak the canary" in note["data"]["detail"]


def test_clean_exit_means_the_payload_did_nothing():
    text = "[Inferior 1 (process 99) exited normally]\n"
    result = PwntoolsParser().parse_text(text, metadata=_META)
    note = result.observations[0].to_dict()

    assert note["data"]["metadata"]["outcome"] == "clean_exit"
    assert note["data"]["severity"] == "info"


def test_repeated_flag_is_deduped():
    text = "flag{dup}\nflag{dup}\n"
    result = PwntoolsParser().parse_text(text)
    assert len([o for o in result.observations if o.kind == "flag"]) == 1


def test_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "nothing interesting happened"):
        result = PwntoolsParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
