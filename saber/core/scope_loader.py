"""Load a mission scope from a simple YAML file."""

from __future__ import annotations

from pathlib import Path

import yaml

from saber.models.scope import MissionScope
from saber.models.target import Target, TargetType


def load_scope(path: str | Path) -> MissionScope:
    """Parse ``{mission_name, targets: [...]}`` YAML into a MissionScope."""

    data = yaml.safe_load(Path(path).read_text()) or {}
    targets = [
        Target(type=TargetType.HOST, value=str(value).strip())
        for value in (data.get("targets") or [])
        if str(value).strip()
    ]
    return MissionScope(
        mission_name=str(data.get("mission_name") or "SABER lab"),
        targets=targets,
    )
