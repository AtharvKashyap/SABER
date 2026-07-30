"""radare2 wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory
from saber.tools.contract import ActionContract, ArgSpec, ToolContract

DEFAULT_ANALYSIS_LEVEL = "aaa"

CONTRACT = ToolContract(
    tool_name="radare2",
    category="reverse_engineering",
    phase="recon",
    description=(
        "Static analysis of a local binary with radare2: auto-analysis, binary "
        "info (arch/bits/protections), function listing (with dangerous-function "
        "triage), and operator-authored r2 command sequences."
    ),
    parser="radare2",
    aliases=("r2",),
    actions=(
        ActionContract(
            action="analyze",
            description=(
                "Run radare2 auto-analysis (aa/aaa/aaaa) over a binary so later "
                "info/functions calls have full analysis available."
            ),
            args=(
                ArgSpec(
                    "binary_path",
                    "str",
                    required=True,
                    description="Path to the binary inside the sandbox.",
                ),
                ArgSpec(
                    "analysis_level",
                    "enum",
                    required=False,
                    default=DEFAULT_ANALYSIS_LEVEL,
                    choices=("aa", "aaa", "aaaa"),
                    description="Analysis depth; aaa is the usual full auto-analysis.",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("note",),
            example_args={"binary_path": "/tmp/challenge.bin", "analysis_level": "aaa"},
        ),
        ActionContract(
            action="info",
            description=(
                "Collect binary info (arch, bits, and hardening protections) with "
                "radare2's `ij`/`i` command, to plan which exploit techniques are viable."
            ),
            args=(
                ArgSpec(
                    "binary_path",
                    "str",
                    required=True,
                    description="Path to the binary inside the sandbox.",
                ),
                ArgSpec(
                    "json_output",
                    "bool",
                    required=False,
                    default=True,
                    description="Use `ij` (JSON) instead of `i` (text).",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("note",),
            example_args={"binary_path": "/tmp/challenge.bin", "json_output": True},
        ),
        ActionContract(
            action="functions",
            description=(
                "List functions with radare2's `aflj`/`afl` command, surfacing "
                "notable/dangerous functions (gets, strcpy, system, memcpy) rather "
                "than the full symbol table."
            ),
            args=(
                ArgSpec(
                    "binary_path",
                    "str",
                    required=True,
                    description="Path to the binary inside the sandbox.",
                ),
                ArgSpec(
                    "json_output",
                    "bool",
                    required=False,
                    default=True,
                    description="Use `aflj` (JSON) instead of `afl` (text).",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("note",),
            example_args={"binary_path": "/tmp/challenge.bin", "json_output": True},
        ),
        ActionContract(
            action="custom_commands",
            description=(
                "Run an operator-authored sequence of radare2 commands. Arbitrary "
                "r2 command execution, so this is approval-gated."
            ),
            args=(
                ArgSpec(
                    "binary_path",
                    "str",
                    required=True,
                    description="Path to the binary inside the sandbox.",
                ),
                ArgSpec(
                    "commands",
                    "list[str]",
                    required=True,
                    description="r2 commands to run in order, e.g. ['aaa', 'afl', 'pdf @main'].",
                ),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("note",),
            example_args={
                "binary_path": "/tmp/challenge.bin",
                "commands": ["aaa", "afl"],
            },
        ),
    ),
)


class Radare2Wrapper(BaseToolWrapper):
    """Wrapper for radare2 static analysis workflows."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize radare2 wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="radare2",
                image="saber/radare2:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.REVERSE_ENGINEERING,
                requested_by="Radare2Wrapper",
                default_timeout_seconds=1200,
                default_metadata={"tool_family": "reverse_engineering", "tool": "radare2"},
            ),
        )

    def analyze(
        self,
        target: Target,
        session: MissionSession,
        binary_path: str,
        analysis_level: str = "aaa",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run radare2 auto-analysis."""

        return self.run(
            target=target,
            session=session,
            action="analyze",
            binary_path=binary_path,
            analysis_level=analysis_level,
            metadata=metadata,
        )

    def info(
        self,
        target: Target,
        session: MissionSession,
        binary_path: str,
        json_output: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Collect binary info with radare2."""

        return self.run(
            target=target,
            session=session,
            action="info",
            binary_path=binary_path,
            json_output=json_output,
            metadata=metadata,
        )

    def functions(
        self,
        target: Target,
        session: MissionSession,
        binary_path: str,
        json_output: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """List functions with radare2."""

        return self.run(
            target=target,
            session=session,
            action="functions",
            binary_path=binary_path,
            json_output=json_output,
            metadata=metadata,
        )

    def custom_commands(
        self,
        target: Target,
        session: MissionSession,
        binary_path: str,
        commands: list[str],
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a custom radare2 command sequence."""

        return self.run(
            target=target,
            session=session,
            action="custom_commands",
            binary_path=binary_path,
            commands=commands,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a radare2 ToolCommand."""

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

        if action == "analyze":
            # The CONTRACT declares analysis_level optional with a default, so
            # apply it rather than raising when the decider omits it.
            analysis_level = self._string_with_default(
                kwargs, "analysis_level", DEFAULT_ANALYSIS_LEVEL
            )
            self._validate_analysis_level(analysis_level)

            return ToolCommand(
                command=["r2", "-q", "-c", analysis_level, "-c", "q", binary_path],
                action="analyze",
                evidence_title=f"radare2 analyze: {binary_path}",
                evidence_relative_dir="reverse_engineering/radare2/analyze",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "analysis_level": analysis_level},
            )

        if action == "info":
            json_output = bool(kwargs.get("json_output", True))
            info_command = "ij" if json_output else "i"

            return ToolCommand(
                command=["r2", "-q", "-c", info_command, "-c", "q", binary_path],
                action="info",
                evidence_title=f"radare2 info: {binary_path}",
                evidence_relative_dir="reverse_engineering/radare2/info",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "json_output": json_output},
            )

        if action == "functions":
            json_output = bool(kwargs.get("json_output", True))
            func_command = "aflj" if json_output else "afl"

            return ToolCommand(
                command=["r2", "-q", "-c", "aaa", "-c", func_command, "-c", "q", binary_path],
                action="functions",
                evidence_title=f"radare2 functions: {binary_path}",
                evidence_relative_dir="reverse_engineering/radare2/functions",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "json_output": json_output},
            )

        if action == "custom_commands":
            raw_commands = kwargs.get("commands")
            if not isinstance(raw_commands, list) or not raw_commands:
                raise ValueError("commands is required")
            commands = self._string_list(raw_commands)
            if not commands:
                raise ValueError("commands is required")

            command = ["r2", "-q"]
            for item in commands:
                command.extend(["-c", item])
            command.extend(["-c", "q", binary_path])

            return ToolCommand(
                command=command,
                action="custom_commands",
                evidence_title=f"radare2 custom commands: {binary_path}",
                evidence_relative_dir="reverse_engineering/radare2/custom_commands",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={**metadata, "commands": commands},
            )

        raise ValueError(f"Unsupported radare2 action: {action}")

    @staticmethod
    def _validate_analysis_level(value: str) -> None:
        """Validate radare2 analysis command."""

        if value not in {"aa", "aaa", "aaaa"}:
            raise ValueError("analysis_level must be one of: aa, aaa, aaaa")

    @staticmethod
    def _required_string(kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()

    @staticmethod
    def _string_list(values: list[Any]) -> list[str]:
        """Normalize a list of string arguments."""

        return [str(value).strip() for value in values if str(value).strip()]

    @staticmethod
    def _string_with_default(kwargs: dict[str, Any], key: str, default: str) -> str:
        """Read a string kwarg, falling back to the CONTRACT-declared default."""

        value = kwargs.get(key)
        if not isinstance(value, str) or not value.strip():
            return default
        return value.strip()
