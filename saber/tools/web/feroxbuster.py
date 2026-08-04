"""Feroxbuster wrapper for SABER."""

from __future__ import annotations

from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.base_wrapper import BaseToolWrapper, ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory
from saber.tools.contract import ActionContract, ArgSpec, ToolContract

# NOTE: the workstream-F plan text called this action "content_discovery", but the
# wrapper's real (and only) build_command dispatch branch is "directory_bruteforce".
# Per the migration template precedent (masscan/dnsrecon/theharvester keep the real
# dispatch name rather than a plan alias), this CONTRACT declares the actual branch
# name so the AST-based coverage gate matches build_command exactly.
CONTRACT = ToolContract(
    tool_name="feroxbuster",
    category="web",
    phase="recon",
    description="Recursive web content discovery (directory/file bruteforce).",
    parser="feroxbuster",
    actions=(
        ActionContract(
            action="directory_bruteforce",
            description="Feroxbuster recursive content discovery, --json output for parsing.",
            args=(
                ArgSpec("url", "str", required=True, description="Base URL in scope."),
                ArgSpec(
                    "wordlist",
                    "str",
                    required=False,
                    default="wordlists/common.txt",
                    description="Wordlist path inside the sandbox.",
                ),
            ),
            risk="medium",
            requires_approval=True,
            emits_kinds=("note",),
            example_args={"url": "http://127.0.0.1/", "wordlist": "wordlists/common.txt"},
        ),
    ),
)


class FeroxbusterWrapper(BaseToolWrapper):
    """Wrapper for Feroxbuster web content discovery."""

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig | None = None) -> None:
        """Initialize Feroxbuster wrapper."""

        super().__init__(
            sandbox=sandbox,
            config=config
            or ToolWrapperConfig(
                tool_name="feroxbuster",
                image="saber/feroxbuster:latest",
                phase=AssessmentPhase.RECON,
                category=RequestedActionCategory.WEB,
                requested_by="FeroxbusterWrapper",
                default_timeout_seconds=1200,
                default_metadata={"tool_family": "web", "tool": "feroxbuster"},
            ),
        )

    def directory_bruteforce(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        wordlist: str = "wordlists/common.txt",
        extensions: list[str] | None = None,
        threads: int = 50,
        output_file: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run directory and file discovery."""

        return self.run(
            target=target,
            session=session,
            action="directory_bruteforce",
            url=url,
            wordlist=wordlist,
            extensions=extensions or [],
            threads=threads,
            output_file=output_file,
            metadata=metadata,
        )

    def quick_scan(
        self,
        target: Target,
        session: MissionSession,
        url: str | None = None,
        wordlist: str = "wordlists/common.txt",
        metadata: dict[str, Any] | None = None,
    ) -> SandboxExecutionResult:
        """Run a smaller Feroxbuster scan."""

        return self.directory_bruteforce(
            target=target,
            session=session,
            url=url,
            wordlist=wordlist,
            threads=20,
            metadata=metadata,
        )

    def build_command(
        self,
        target: Target | str | None = None,
        action: str | None = None,
        **kwargs: Any,
    ) -> ToolCommand:
        """Build a Feroxbuster ToolCommand."""

        if isinstance(target, str) and action is None:
            action = target
            target = None
        if action is None:
            raise ValueError("action is required")
        if action != "directory_bruteforce":
            raise ValueError(f"Unsupported Feroxbuster action: {action}")

        url = self._url_from_target_or_kwargs(target, kwargs)
        wordlist = self._wordlist_from_kwargs(kwargs)
        threads = self._positive_int(kwargs.get("threads", 50), "threads")

        command = ["feroxbuster", "-u", url, "-w", wordlist, "--json", "-t", str(threads)]

        extensions = self._string_list(kwargs.get("extensions") or [])
        if extensions:
            command.extend(["-x", ",".join(extensions)])

        output_file = kwargs.get("output_file")
        if output_file:
            command.extend(["-o", str(output_file)])

        return ToolCommand(
            command=command,
            action="directory_bruteforce",
            evidence_title=f"Feroxbuster directory bruteforce: {url}",
            evidence_relative_dir="web/feroxbuster/directory_bruteforce",
            timeout_seconds=kwargs.get("timeout_seconds"),
            metadata={
                "action": action,
                "url": url,
                "wordlist": wordlist,
                "extensions": extensions,
                "threads": threads,
                "output_file": output_file,
                "target": target.tool_value() if isinstance(target, Target) else None,
                **(kwargs.get("metadata") or {}),
            },
        )

    @classmethod
    def _wordlist_from_kwargs(cls, kwargs: dict[str, Any]) -> str:
        """Resolve wordlist from kwargs, defaulting when omitted entirely."""

        if "wordlist" in kwargs and kwargs["wordlist"] is not None:
            return cls._string_value(kwargs["wordlist"], "wordlist")
        return "wordlists/common.txt"

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
    def _string_list(values: list[Any]) -> list[str]:
        """Normalize a list of string values."""

        return [str(value).strip() for value in values if str(value).strip()]

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
