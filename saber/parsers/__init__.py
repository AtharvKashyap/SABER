"""Output parsers for SABER.

Parsers convert raw tool stdout/stderr/files into normalized observations and
findings for agents, orchestration, storage, and reporting.

Tool wrappers run commands.
Parsers interpret command output.

This package intentionally avoids eager imports to reduce circular import risk.
"""

__all__: list[str] = []
PY