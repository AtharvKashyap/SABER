"""Hashcat wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class HashcatWrapper(BaseToolWrapper):
    """Wrapper for Hashcat password-auditing workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Hashcat wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="hashcat",
                image="saber/hashcat:latest",
                phase=AssessmentPhase.EXPLOITATION,
                category=RequestedActionCategory.PASSWORD_CRACKING,
                requested_by="HashcatWrapper",
                default_timeout_seconds=3600,
                default_metadata={"tool_family": "password", "tool": "hashcat"},
            ),
        )

    def dictionary_attack(
        self,
        target: Target,
        session: MissionSession,
        hash_file: str,
        hash_mode: str | int,
        wordlist: str,
        rules: list[str] | None = None,
        workload_profile: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a Hashcat dictionary attack."""

        return self.run(
            target=target,
            session=session,
            action="dictionary_attack",
            hash_file=hash_file,
            hash_mode=hash_mode,
            wordlist=wordlist,
            rules=rules or [],
            workload_profile=workload_profile,
            metadata=metadata,
        )

    def mask_attack(
        self,
        target: Target,
        session: MissionSession,
        hash_file: str,
        hash_mode: str | int,
        mask: str,
        workload_profile: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a Hashcat mask attack."""

        return self.run(
            target=target,
            session=session,
            action="mask_attack",
            hash_file=hash_file,
            hash_mode=hash_mode,
            mask=mask,
            workload_profile=workload_profile,
            metadata=metadata,
        )

    def show_cracked(
        self,
        target: Target,
        session: MissionSession,
        hash_file: str,
        hash_mode: str | int,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Show cracked hashes from Hashcat potfile."""

        return self.run(
            target=target,
            session=session,
            action="show_cracked",
            hash_file=hash_file,
            hash_mode=hash_mode,
            metadata=metadata,
        )

    def benchmark(
        self,
        target: Target,
        session: MissionSession,
        hash_mode: str | int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run Hashcat benchmark."""

        return self.run(
            target=target,
            session=session,
            action="benchmark",
            hash_mode=hash_mode,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a Hashcat ToolCommand."""

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

        if action == "dictionary_attack":
            hash_file = self._required_string(kwargs, "hash_file")
            hash_mode = self._required_string(kwargs, "hash_mode")
            wordlist = self._required_string(kwargs, "wordlist")
            command = ["hashcat", "-m", hash_mode, "-a", "0", hash_file, wordlist]
            for rule in kwargs.get("rules") or []:
                rule_value = str(rule).strip()
                if rule_value:
                    command.extend(["-r", rule_value])
            workload_profile = kwargs.get("workload_profile")
            if workload_profile is not None:
                command.extend(["-w", str(self._positive_int(workload_profile, "workload_profile"))])

            return ToolCommand(
                command=command,
                action="dictionary_attack",
                evidence_title=f"Hashcat dictionary attack: {hash_file}",
                evidence_relative_dir="password/hashcat/dictionary",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "hash_file": hash_file,
                    "hash_mode": hash_mode,
                    "wordlist": wordlist,
                    "rules": kwargs.get("rules") or [],
                    "workload_profile": workload_profile,
                },
            )

        if action == "mask_attack":
            hash_file = self._required_string(kwargs, "hash_file")
            hash_mode = self._required_string(kwargs, "hash_mode")
            mask = self._required_string(kwargs, "mask")
            command = ["hashcat", "-m", hash_mode, "-a", "3", hash_file, mask]
            workload_profile = kwargs.get("workload_profile")
            if workload_profile is not None:
                command.extend(["-w", str(self._positive_int(workload_profile, "workload_profile"))])

            return ToolCommand(
                command=command,
                action="mask_attack",
                evidence_title=f"Hashcat mask attack: {hash_file}",
                evidence_relative_dir="password/hashcat/mask",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "hash_file": hash_file,
                    "hash_mode": hash_mode,
                    "mask": mask,
                    "workload_profile": workload_profile,
                },
            )

        if action == "show_cracked":
            hash_file = self._required_string(kwargs, "hash_file")
            hash_mode = self._required_string(kwargs, "hash_mode")

            return ToolCommand(
                command=["hashcat", "-m", hash_mode, "--show", hash_file],
                action="show_cracked",
                evidence_title=f"Hashcat show cracked: {hash_file}",
                evidence_relative_dir="password/hashcat/show",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "hash_file": hash_file, "hash_mode": hash_mode},
            )

        if action == "benchmark":
            command = ["hashcat", "-b"]
            hash_mode = kwargs.get("hash_mode")
            if hash_mode is not None:
                command.extend(["-m", self._string_value(hash_mode, "hash_mode")])

            return ToolCommand(
                command=command,
                action="benchmark",
                evidence_title="Hashcat benchmark",
                evidence_relative_dir="password/hashcat/benchmark",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "hash_mode": str(hash_mode) if hash_mode is not None else None},
            )

        raise ValueError(f"Unsupported Hashcat action: {action}")

    @classmethod
    def _required_string(cls, kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string-like argument."""

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
        """Validate a positive integer value."""

        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be a positive integer") from exc
        if parsed <= 0:
            raise ValueError(f"{key} must be a positive integer")
        return parsed
