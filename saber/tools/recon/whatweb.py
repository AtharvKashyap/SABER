"""WhatWeb wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class WhatWebWrapper(BaseToolWrapper):
    """Wrapper for WhatWeb web technology fingerprinting."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize WhatWeb wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="whatweb",
                image="saber/whatweb:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.RECON,
                requested_by="WhatWebWrapper",
                default_timeout_seconds=600,
                default_metadata={"tool_family": "recon", "tool": "whatweb"},
            ),
        )

    def fingerprint(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        aggression: int = 1,
        json_output: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Fingerprint a single web target."""

        return self.run(
            target=target,
            session=session,
            action="fingerprint",
            url=url,
            aggression=aggression,
            json_output=json_output,
            metadata=metadata,
        )

    def aggressive(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        json_output: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run aggressive WhatWeb fingerprinting."""

        return self.run(
            target=target,
            session=session,
            action="aggressive",
            url=url,
            json_output=json_output,
            metadata=metadata,
        )

    def list_scan(
        self,
        target: Target,
        session: MissionSession,
        input_file: str,
        aggression: int = 1,
        json_output: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Fingerprint URLs from an input file."""

        return self.run(
            target=target,
            session=session,
            action="list_scan",
            input_file=input_file,
            aggression=aggression,
            json_output=json_output,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a WhatWeb ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        metadata = {
            "action": action,
            "target": target.tool_value() if isinstance(target, Target) else None,
            **(kwargs.get("metadata") or {}),
        }

        if action in {"fingerprint", "aggressive"}:
            url = self._url_from_target_or_kwargs(target, kwargs)
            aggression = 3 if action == "aggressive" else self._positive_int(kwargs.get("aggression", 1), "aggression")
            command = ["whatweb", "-a", str(aggression), url]

            json_output = kwargs.get("json_output")
            if json_output:
                command.extend(["--log-json", str(json_output)])

            evidence_dir = "recon/whatweb/aggressive" if action == "aggressive" else "recon/whatweb/fingerprint"

            return ToolCommand(
                command=command,
                action=action,
                evidence_title=f"WhatWeb {action}: {url}",
                evidence_relative_dir=evidence_dir,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "url": url, "aggression": aggression, "json_output": json_output},
            )

        if action == "list_scan":
            input_file = self._required_string(kwargs, "input_file")
            aggression = self._positive_int(kwargs.get("aggression", 1), "aggression")
            command = ["whatweb", "-a", str(aggression), "-i", input_file]

            json_output = kwargs.get("json_output")
            if json_output:
                command.extend(["--log-json", str(json_output)])

            return ToolCommand(
                command=command,
                action="list_scan",
                evidence_title=f"WhatWeb list scan: {input_file}",
                evidence_relative_dir="recon/whatweb/list_scan",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "input_file": input_file, "aggression": aggression, "json_output": json_output},
            )

        raise ValueError(f"Unsupported WhatWeb action: {action}")

    @classmethod
    def _url_from_target_or_kwargs(cls, target: Target | str | None, kwargs: dict[str, Any]) -> str:
        """Resolve URL from explicit kwarg or Target."""

        explicit = kwargs.get("url")
        if explicit is not None:
            return cls._string_value(explicit, "url")
        if isinstance(target, Target):
            return cls._string_value(target.tool_value(), "url")
        return cls._required_string(kwargs, "url")

    @classmethod
    def _required_string(cls, kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        if key not in kwargs:
            raise ValueError(f"{key} is required")
        return cls._string_value(kwargs[key], key)

    @staticmethod
    def _string_value(value: Any, key: str) -> str:
        """Convert and validate a string-like value."""

        text = str(value).strip()
        if not text:
            raise ValueError(f"{key} is required")
        return text

    @staticmethod
    def _positive_int(value: Any, key: str) -> int:
        """Validate a positive integer."""

        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be a positive integer") from exc
        if parsed <= 0:
            raise ValueError(f"{key} must be a positive integer")
        return parsed

    @staticmethod
    def _validate_aggression(value: Any) -> int:
        """Validate WhatWeb aggression level.

        WhatWeb accepts 1, 3, or 4. Level 1 is safest/default.
        """

        try:
            aggression = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("aggression must be one of: 1, 3, 4") from exc

        if aggression not in {1, 3, 4}:
            raise ValueError("aggression must be one of: 1, 3, 4")

        return aggression

