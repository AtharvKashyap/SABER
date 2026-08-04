"""Shared test fixtures and helpers for SABER."""

from __future__ import annotations

from saber.core.state_merger import StateMerger
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.target import Target, TargetType


def assert_observation(obs: dict, *, kind: str, data_subset: dict) -> None:
    """Assert an observation has the given kind and its data is a superset of data_subset."""
    assert obs["kind"] == kind, f"expected kind={kind!r}, got {obs['kind']!r}"
    for key, value in data_subset.items():
        assert obs["data"].get(key) == value, (
            f"data[{key!r}]: expected {value!r}, got {obs['data'].get(key)!r}"
        )


def merge_observations(observations: list[dict], *, tool: str, action: str) -> MissionState:
    """Merge a list of {kind,data} observations into a fresh MissionState and return it."""
    state = MissionState(session_id="test", target=Target(type=TargetType.IP, value="127.0.0.1"))
    attempt = AttemptedAction(tool_name=tool, action=action, args={}, success=True)
    return StateMerger().merge(state, observations, attempt)
