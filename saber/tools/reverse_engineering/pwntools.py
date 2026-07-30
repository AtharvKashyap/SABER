"""pwntools / gdb wrapper for SABER binary exploitation.

This wrapper is deliberately STATELESS. It does not solve anything: it runs a
pwntools script that the decider authored, and hands the program's output back to
the loop as observations. The iteration — read the crash, revise the script, run it
again — is the decider's job (F8), not this module's.

That split matters for two reasons:

- **The invariant holds.** No subprocess here. The wrapper only builds a
  ``ToolCommand``; ``Sandbox`` executes it, like every other tool.
- **It is honest.** SABER is not a general exploit solver. It is structured
  iteration: the model writes an attempt, sees what actually happened, and writes a
  better one. Whether that converges depends on the binary.

The decider authors the script through ``custom_cli`` (a heredoc into a file under
the sandbox workspace), then points ``run_exploit`` at that path.
"""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory
from saber.tools.contract import ActionContract, ArgSpec, ToolContract

CONTRACT = ToolContract(
    tool_name="pwntools",
    category="reverse_engineering",
    phase="exploitation",
    description=(
        "Run a pwntools exploit script against a local binary, or drive it under gdb. "
        "Use after checksec/radare2 have shown which mitigations are missing: write a "
        "script with custom_cli, run it here, read the output, and revise. Program "
        "output (crashes, leaks, flags) comes back as observations to iterate on."
    ),
    parser="pwntools",
    actions=(
        ActionContract(
            action="run_exploit",
            description=(
                "Run a pwntools script you have already written against a binary. The "
                "script receives the binary path as argv[1]. Read the returned output "
                "and revise the script if it did not work."
            ),
            args=(
                ArgSpec(
                    "binary_path",
                    "str",
                    required=True,
                    description="Path to the target binary inside the sandbox.",
                ),
                ArgSpec(
                    "script_path",
                    "str",
                    required=True,
                    description=(
                        "Path to the pwntools script to run. Write it first with "
                        "custom_cli.run_command (heredoc into a file)."
                    ),
                ),
                ArgSpec(
                    "argv",
                    "list[str]",
                    required=False,
                    description="Extra arguments appended after the binary path.",
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("flag", "note"),
            example_args={
                "binary_path": "/opt/lab/vulnbin",
                "script_path": "/workspace/tmp/exploit.py",
            },
        ),
        ActionContract(
            action="debug",
            description=(
                "Run the binary under gdb in batch mode with a gdb script, to inspect a "
                "crash, find an offset, or read memory. Non-interactive."
            ),
            args=(
                ArgSpec(
                    "binary_path",
                    "str",
                    required=True,
                    description="Path to the target binary inside the sandbox.",
                ),
                ArgSpec(
                    "gdb_script",
                    "str",
                    required=False,
                    description=(
                        "Path to a gdb command file (-x). Without it, gdb just runs the "
                        "binary and reports how it terminated."
                    ),
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("flag", "note"),
            example_args={"binary_path": "/opt/lab/vulnbin"},
        ),
    ),
)


class PwntoolsWrapper(BaseToolWrapper):
    """Run decider-authored pwntools scripts and gdb batch sessions in the sandbox."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize the pwntools wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="pwntools",
                image="saber/pwntools:latest",
                phase=AssessmentPhase.EXPLOITATION,
                category=RequestedActionCategory.REVERSE_ENGINEERING,
                requested_by="PwntoolsWrapper",
                default_timeout_seconds=300,
                default_metadata={"tool_family": "reverse_engineering", "tool": "pwntools"},
            ),
        )

    def run_exploit(
        self,
        target: Target,
        session: MissionSession,
        binary_path: str,
        script_path: str,
        argv: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a pwntools exploit script against a binary."""

        return self.run(
            target=target,
            session=session,
            action="run_exploit",
            binary_path=binary_path,
            script_path=script_path,
            argv=argv or [],
            metadata=metadata,
        )

    def debug(
        self,
        target: Target,
        session: MissionSession,
        binary_path: str,
        gdb_script: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a binary under gdb in batch mode."""

        return self.run(
            target=target,
            session=session,
            action="debug",
            binary_path=binary_path,
            gdb_script=gdb_script,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a pwntools/gdb ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")

        binary_path = self._required_string(kwargs, "binary_path")
        metadata = {
            "action": action,
            "target": target.tool_value() if isinstance(target, Target) else None,
            "binary_path": binary_path,
            **(kwargs.get("metadata") or {}),
        }

        if action == "run_exploit":
            script_path = self._required_string(kwargs, "script_path")
            extra = [str(item).strip() for item in (kwargs.get("argv") or []) if str(item).strip()]

            return ToolCommand(
                # The script is run by python3, NOT bash: pwntools scripts are Python.
                # custom_cli.run_script uses bash and cannot run these.
                command=["python3", script_path, binary_path, *extra],
                action="run_exploit",
                evidence_title=f"pwntools exploit: {binary_path}",
                evidence_relative_dir="reverse_engineering/pwntools/run_exploit",
                requires_explicit_authorization=True,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "script_path": script_path, "argv": extra},
            )

        if action == "debug":
            gdb_script = kwargs.get("gdb_script")
            command = ["gdb", "--batch"]
            if gdb_script:
                command.extend(["-x", self._string_value(gdb_script, "gdb_script")])
            command.append(binary_path)

            return ToolCommand(
                command=command,
                action="debug",
                evidence_title=f"gdb batch: {binary_path}",
                evidence_relative_dir="reverse_engineering/pwntools/debug",
                requires_explicit_authorization=True,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "gdb_script": gdb_script},
            )

        raise ValueError(f"Unsupported pwntools action: {action}")

    @classmethod
    def _required_string(cls, kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        if key not in kwargs:
            raise ValueError(f"{key} is required")
        return cls._string_value(kwargs[key], key)

    @staticmethod
    def _string_value(value: Any, key: str) -> str:
        """Convert and validate a string-like value."""

        text = str(value).strip() if value is not None else ""
        if not text:
            raise ValueError(f"{key} is required")
        return text
