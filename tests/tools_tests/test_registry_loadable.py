"""Every registered tool must actually import.

A registry entry whose ``import_path``/``class_name`` is wrong is worse than a
missing entry: the tool appears registered, so nothing flags it, but every
attempt to run it dies at ``load_class()``. ``impacket`` shipped that way — the
entry pointed at ``saber.tools.active_directory.impacket`` (real module:
``impacket_tools``) and named ``ImpacketWrapper`` (real class:
``ImpacketToolsWrapper``), so the whole tool was unusable while looking present.
"""

from __future__ import annotations

import pytest
from saber.tools.base_wrapper import BaseToolWrapper
from saber.tools.registry import build_default_registry


def _registered_names() -> list[str]:
    """Return one canonical name per registered entry (not per alias)."""

    registry = build_default_registry()
    entries = getattr(registry, "_entries", {})
    return sorted({entry.name for entry in entries.values()})


def test_registry_is_not_empty():
    assert _registered_names(), "tool registry exposed no entries"


@pytest.mark.parametrize("tool_name", _registered_names())
def test_registered_tool_class_is_importable(tool_name):
    """load_class() must succeed for every registered tool."""

    entry = build_default_registry().get(tool_name)
    try:
        wrapper_class = entry.load_class()
    except Exception as exc:  # noqa: BLE001 - the failure is the finding
        pytest.fail(
            f"{tool_name} is registered but not loadable: {type(exc).__name__}: {exc}. "
            f"Check import_path={entry.import_path!r} class_name={entry.class_name!r}."
        )
    assert issubclass(wrapper_class, BaseToolWrapper)
