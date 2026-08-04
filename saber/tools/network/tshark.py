"""tshark passive-capture wrapper for SABER.

Passive capture is the one recon method that finds things active scanning cannot:
hosts that never answer a probe but do talk, and cleartext credentials in transit.

Two actions rather than the one the plan listed:

- ``capture`` puts the interface in promiscuous mode and writes a pcap. High risk,
  approval-gated — it observes other people's traffic, so it goes THROUGH RiskGate
  like anything else, never around it.
- ``read_pcap`` re-analyses a capture already on disk. No traffic, no privileges, so
  it is low risk and autonomous. Without it a pcap is loot nobody ever reads; with
  it the loop can come back and re-filter the same capture as it learns what to
  look for.
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

DEFAULT_CAPTURE_SECONDS = 30
DEFAULT_PCAP_PATH = "/workspace/output/capture.pcap"

CONTRACT = ToolContract(
    tool_name="tshark",
    category="network",
    phase="recon",
    description=(
        "Passive traffic capture and pcap analysis. Finds hosts that never answer an "
        "active probe, the protocols actually in use, and credentials sent in the clear."
    ),
    parser="tshark",
    actions=(
        ActionContract(
            action="capture",
            description=(
                "Capture live traffic on an interface for a fixed duration and write a "
                "pcap. Observes other hosts' traffic, so it is approval-gated."
            ),
            args=(
                ArgSpec(
                    "interface",
                    "str",
                    required=True,
                    description="Interface to capture on, e.g. eth0.",
                ),
                ArgSpec(
                    "duration",
                    "int",
                    required=False,
                    default=DEFAULT_CAPTURE_SECONDS,
                    example=30,
                    description="Seconds to capture for (-a duration:N).",
                ),
                ArgSpec(
                    "capture_filter",
                    "str",
                    required=False,
                    description="BPF capture filter, e.g. 'tcp port 21 or tcp port 80'.",
                ),
                ArgSpec(
                    "output_file",
                    "str",
                    required=False,
                    default=DEFAULT_PCAP_PATH,
                    description="Where to write the pcap.",
                ),
            ),
            risk="high",
            requires_approval=True,
            emits_kinds=("host", "note", "credential", "loot"),
            example_args={"interface": "eth0", "duration": 30},
        ),
        ActionContract(
            action="read_pcap",
            description=(
                "Analyse a pcap already on disk, optionally with a display filter. "
                "Touches no network, so it can be re-run freely as the mission learns "
                "what to look for."
            ),
            args=(
                ArgSpec(
                    "pcap_path",
                    "str",
                    required=True,
                    description="Path to an existing pcap inside the sandbox.",
                ),
                ArgSpec(
                    "display_filter",
                    "str",
                    required=False,
                    description="tshark display filter (-Y), e.g. 'http.authorization'.",
                ),
            ),
            risk="low",
            requires_approval=False,
            emits_kinds=("host", "note", "credential", "loot"),
            example_args={"pcap_path": DEFAULT_PCAP_PATH},
        ),
    ),
)


class TsharkWrapper(BaseToolWrapper):
    """Capture traffic passively and analyse captures, via tshark."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize the tshark wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="tshark",
                image="saber/tshark:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.NETWORK,
                requested_by="TsharkWrapper",
                default_timeout_seconds=600,
                default_metadata={"tool_family": "network", "tool": "tshark"},
            ),
        )

    def capture(
        self,
        target: Target,
        session: MissionSession,
        interface: str,
        duration: int = DEFAULT_CAPTURE_SECONDS,
        capture_filter: str | None = None,
        output_file: str = DEFAULT_PCAP_PATH,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Capture live traffic on an interface."""

        return self.run(
            target=target,
            session=session,
            action="capture",
            interface=interface,
            duration=duration,
            capture_filter=capture_filter,
            output_file=output_file,
            metadata=metadata,
        )

    def read_pcap(
        self,
        target: Target,
        session: MissionSession,
        pcap_path: str,
        display_filter: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Analyse an existing pcap."""

        return self.run(
            target=target,
            session=session,
            action="read_pcap",
            pcap_path=pcap_path,
            display_filter=display_filter,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a tshark ToolCommand."""

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

        if action == "capture":
            interface = self._required_string(kwargs, "interface")
            duration = self._positive_int(kwargs.get("duration", DEFAULT_CAPTURE_SECONDS))
            output_file = self._string_with_default(kwargs, "output_file", DEFAULT_PCAP_PATH)

            command = [
                "tshark",
                "-i",
                interface,
                "-a",
                f"duration:{duration}",
                "-w",
                output_file,
            ]
            capture_filter = kwargs.get("capture_filter")
            if capture_filter:
                command.extend(["-f", str(capture_filter).strip()])

            return ToolCommand(
                command=command,
                action="capture",
                evidence_title=f"tshark capture: {interface} ({duration}s)",
                evidence_relative_dir="network/tshark/capture",
                requires_explicit_authorization=True,
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "interface": interface,
                    "duration": duration,
                    "output_file": output_file,
                    "capture_filter": capture_filter,
                },
            )

        if action == "read_pcap":
            pcap_path = self._required_string(kwargs, "pcap_path")
            # -T json gives the parser structured layers instead of a text summary.
            command = ["tshark", "-r", pcap_path, "-T", "json"]
            display_filter = kwargs.get("display_filter")
            if display_filter:
                command.extend(["-Y", str(display_filter).strip()])

            return ToolCommand(
                command=command,
                action="read_pcap",
                evidence_title=f"tshark read: {pcap_path}",
                evidence_relative_dir="network/tshark/read_pcap",
                timeout_seconds=kwargs.get("timeout_seconds"),
                metadata={
                    **metadata,
                    "pcap_path": pcap_path,
                    "display_filter": display_filter,
                },
            )

        raise ValueError(f"Unsupported tshark action: {action}")

    @classmethod
    def _required_string(cls, kwargs: dict[str, Any], key: str) -> str:
        """Read and validate a required string."""

        value = kwargs.get(key)
        text = str(value).strip() if value is not None else ""
        if not text:
            raise ValueError(f"{key} is required")
        return text

    @staticmethod
    def _string_with_default(kwargs: dict[str, Any], key: str, default: str) -> str:
        """Read a string kwarg, falling back to the CONTRACT-declared default."""

        value = kwargs.get(key)
        text = str(value).strip() if value is not None else ""
        return text or default

    @staticmethod
    def _positive_int(value: Any) -> int:
        """Validate a positive capture duration."""

        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("duration must be a positive integer") from exc
        if parsed <= 0:
            raise ValueError("duration must be a positive integer")
        return parsed
