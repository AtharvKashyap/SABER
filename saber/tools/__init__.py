

"""Tool wrapper exports for SABER.

The `saber.tools` package contains safe wrapper classes that translate
high-level assessment actions into SandboxExecutionRequest objects. Tool wrappers
must not execute shell commands directly; execution must flow through Sandbox,
ScopeGuard, ApprovalGate, DockerRunner, and EvidenceStore.

Only stable shared wrapper APIs should be exported here. Individual tool wrappers
such as NmapWrapper, WhatWebWrapper, and NucleiWrapper should be added after they
are implemented and tested.
"""

from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig

__all__ = [
    "BaseToolWrapper",
    "ToolCommand",
    "ToolWrapperConfig",
]