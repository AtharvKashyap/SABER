"""John the Ripper wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory


class JohnWrapper(BaseToolWrapper):
    """Wrapper for John the Ripper password-auditing workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize John wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="john",
                image="saber/john:latest",
                phase=AssessmentPhase.EXPLOITATION,
                category=RequestedActionCategory.PASSWORD_CRACKING,
                requested_by="JohnWrapper",
                default_timeout_seconds=3600,
                default_metadata={"tool_family": "password", "tool": "john"},
            ),
        )

    def dictionary_attack(
        self,
        target: Target,
        session: MissionSession,
        hash_file: str,
        wordlist: str,
        format_name: str | None = None,
        rules: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run John dictionary attack."""

        return self.run(
            target=target,
            session=session,
            action="dictionary_attack",
            hash_file=hash_file,
            wordlist=wordlist,
            format_name=format_name,
            rules=rules,
            metadata=metadata,
        )

    def single_crack(
        self,
        target: Target,
        session: MissionSession,
        hash_file: str,
        format_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run John single-crack mode."""

        return self.run(
            target=target,
            session=session,
            action="single_crack",
            hash_file=hash_file,
            format_name=format_name,
            metadata=metadata,
        )

    def show_cracked(
        self,
        target: Target,
        session: MissionSession,
        hash_file: str,
        format_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Show John cracked hashes."""

        return self.run(
            target=target,
            session=session,
            action="show_cracked",
            hash_file=hash_file,
            format_name=format_name,
            metadata=metadata,
        )

    def list_formats(
        self,
        target: Target,
        session: MissionSession,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """List John hash formats."""

        return self.run(target=target, session=session, action="list_formats", metadata=metadata)

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a John ToolCommand."""

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
            wordlist = self._required_string(kwargs, "wordlist")
            command = ["john", f"--wordlist={wordlist}"]
            format_name = kwargs.get("format_name")
            rules = kwargs.get("rules")
            if format_name:
                command.append(f"--format={str(format_name).strip()}")
            if rules:
                command.append(f"--rules={str(rules).strip()}")
            command.append(hash_file)

            return ToolCommand(
                command=command,
                action="dictionary_attack",
                evidence_title=f"John dictionary attack: {hash_file}",
                evidence_relative_dir="password/john/dictionary",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "hash_file": hash_file,
                    "wordlist": wordlist,
                    "format_name": str(format_name).strip() if format_name else None,
                    "rules": str(rules).strip() if rules else None,
                },
            )

        if action == "single_crack":
            hash_file = self._required_string(kwargs, "hash_file")
            command = ["john", "--single"]
            format_name = kwargs.get("format_name")
            if format_name:
                command.append(f"--format={str(format_name).strip()}")
            command.append(hash_file)

            return ToolCommand(
                command=command,
                action="single_crack",
                evidence_title=f"John single crack: {hash_file}",
                evidence_relative_dir="password/john/single",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "hash_file": hash_file,
                    "format_name": str(format_name).strip() if format_name else None,
                },
            )

        if action == "show_cracked":
            hash_file = self._required_string(kwargs, "hash_file")
            command = ["john", "--show"]
            format_name = kwargs.get("format_name")
            if format_name:
                command.append(f"--format={str(format_name).strip()}")
            command.append(hash_file)

            return ToolCommand(
                command=command,
                action="show_cracked",
                evidence_title=f"John show cracked: {hash_file}",
                evidence_relative_dir="password/john/show",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "hash_file": hash_file,
                    "format_name": str(format_name).strip() if format_name else None,
                },
            )

        if action == "list_formats":
            return ToolCommand(
                command=["john", "--list=formats"],
                action="list_formats",
                evidence_title="John list formats",
                evidence_relative_dir="password/john/formats",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata=metadata,
            )

        raise ValueError(f"Unsupported John action: {action}")

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()
