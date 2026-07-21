"""MissionOrchestrator must require a mission_loop; None is rejected."""

from unittest.mock import MagicMock

import pytest
from saber.orchestration.mission_orchestrator import MissionOrchestrator


def test_orchestrator_requires_mission_loop():
    with pytest.raises(ValueError):
        MissionOrchestrator(
            agents={"a": MagicMock()},
            tool_registry=MagicMock(),
            sandbox=MagicMock(),
            mission_loop=None,
        )
