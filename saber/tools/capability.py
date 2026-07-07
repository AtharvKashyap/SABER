"""Shared tool capability models for SABER.

These lightweight objects describe what a tool wants to run. They are not a
heavy policy or approval system; they are just the common request shape used by
tool wrappers, sandbox execution, agents, and registries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from saber.models.scope import AssessmentPhase
from saber.models.target import Target


class RequestedActionCategory(StrEnum):
    """High-level category for a requested tool action."""

    RECON = "recon"
    WEB = "web"
    NETWORK = "network"
    ACTIVE_DIRECTORY = "active_directory"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PASSWORD_CRACKING = "password_cracking"
    REVERSE_ENGINEERING = "reverse_engineering"
    LATERAL_MOVEMENT = "lateral_movement"
    REPORTING = "reporting"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ToolRequest:
    """Lightweight description of a tool action."""

    tool_name: str
    action: str
    phase: AssessmentPhase
    target: Target | None = None
    category: RequestedActionCategory = RequestedActionCategory.UNKNOWN
    requires_explicit_authorization: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
