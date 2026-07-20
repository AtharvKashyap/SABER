"""SABER runtime builder.

This module wires configuration, storage, tools, parsers, result processing, and
orchestration into one runtime object.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from saber.agents.exploit_agent import ExploitAgent
from saber.agents.lateral_movement_agent import LateralMovementAgent
from saber.agents.network_agent import NetworkAgent
from saber.agents.planner_agent import PlannerAgent
from saber.agents.post_exploit_agent import PostExploitAgent
from saber.agents.recon_agent import ReconAgent
from saber.agents.reporter_agent import ReporterAgent
from saber.agents.reverse_engineering_agent import ReverseEngineerAgent
from saber.agents.web_agent import WebAgent
from saber.core.docker_runner import DockerSubprocessRunner
from saber.core.env_loader import load_env_file
from saber.core.evidence_store import EvidenceStore
from saber.core.llm_client import LlmClient, LlmConfig
from saber.core.result_processor import ResultProcessor
from saber.core.tool_catalog import ToolCatalog
from saber.core.sandbox import Sandbox
from saber.orchestration.chain_runner import ChainRunner
from saber.orchestration.mission_orchestrator import MissionOrchestrator
from saber.orchestration.step_runner import StepRunner
from saber.parsers.registry import ParserRegistry, build_default_parser_registry
from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore
from saber.storage.session_store import SessionStore
from saber.tools.registry import ToolRegistry, build_default_registry


@dataclass(frozen=True)
class SaberConfig:
    """Runtime configuration for SABER."""

    db_path: Path = Path("runs/saber.db")
    evidence_dir: Path = Path("runs/evidence")
    reports_dir: Path = Path("runs/reports")
    profile: str = "recon"
    require_approval: bool = True
    sandbox_backend: str = "docker"
    sandbox_image: str = "ghcr.io/atharvkashyap/saber-sandbox:kali-last-release"
    docker_network: str = "host"
    docker_user: str = ""
    default_timeout_seconds: int = 300
    max_steps: int = 50
    max_chain_depth: int = 20
    agent_mode: str = "deterministic"
    allowed_tools: tuple[str, ...] = ()
    disabled_tools: tuple[str, ...] = ()
    llm_config: LlmConfig = field(default_factory=LlmConfig.from_env)
    metadata: dict[str, Any] | None = None

    @classmethod
    def from_env(cls) -> SaberConfig:
        """Build config from environment variables."""

        load_env_file()

        return cls(
            db_path=Path(os.environ.get("SABER_DB_PATH", "runs/saber.db")),
            evidence_dir=Path(os.environ.get("SABER_EVIDENCE_DIR", "runs/evidence")),
            reports_dir=Path(os.environ.get("SABER_REPORTS_DIR", "runs/reports")),
            profile=os.environ.get("SABER_PROFILE", "recon"),
            require_approval=_env_bool("SABER_REQUIRE_APPROVAL", default=True),
            sandbox_backend=os.environ.get("SABER_SANDBOX_BACKEND", "docker"),
            sandbox_image=os.environ.get(
                "SABER_SANDBOX_IMAGE",
                "ghcr.io/atharvkashyap/saber-sandbox:kali-last-release",
            ),
            docker_network=os.environ.get("SABER_DOCKER_NETWORK", "host"),
            docker_user=os.environ.get("SABER_DOCKER_USER", ""),
            default_timeout_seconds=int(os.environ.get("SABER_DEFAULT_TIMEOUT_SECONDS", "300")),
            max_steps=int(os.environ.get("SABER_MAX_STEPS", "50")),
            max_chain_depth=int(os.environ.get("SABER_MAX_CHAIN_DEPTH", "20")),
            allowed_tools=_env_csv("SABER_ALLOWED_TOOLS"),
            disabled_tools=_env_csv("SABER_DISABLED_TOOLS"),
            metadata={"source": "env"},
        )

    def ensure_directories(self) -> None:
        """Create runtime directories."""

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class SaberRuntime:
    """Fully wired SABER runtime."""

    config: SaberConfig
    storage_connection: StorageConnection
    session_store: SessionStore
    evidence_index: EvidenceIndex
    finding_store: FindingStore
    graph_store: GraphStore
    tool_registry: ToolRegistry
    parser_registry: ParserRegistry
    tool_catalog: ToolCatalog
    llm_client: LlmClient
    result_processor: ResultProcessor
    sandbox: Sandbox
    agents: dict[str, Any]
    step_runner: StepRunner
    chain_runner: ChainRunner
    orchestrator: MissionOrchestrator

    def close(self) -> None:
        """Close runtime resources."""

        self.storage_connection.close()

    def to_dict(self) -> dict[str, Any]:
        """Return runtime summary."""

        return {
            "config": {
                "db_path": str(self.config.db_path),
                "evidence_dir": str(self.config.evidence_dir),
                "reports_dir": str(self.config.reports_dir),
                "profile": self.config.profile,
                "require_approval": self.config.require_approval,
                "sandbox_backend": self.config.sandbox_backend,
                "sandbox_image": self.config.sandbox_image,
                "docker_network": self.config.docker_network,
                "docker_user": self.config.docker_user,
                "default_timeout_seconds": self.config.default_timeout_seconds,
                "max_steps": self.config.max_steps,
                "max_chain_depth": self.config.max_chain_depth,
                "allowed_tools": list(self.config.allowed_tools),
                "disabled_tools": list(self.config.disabled_tools),
            },
            "parsers": self.parser_registry.list_entries(),
            "agents": sorted(self.agents.keys()),
            "sandbox": self.sandbox.__class__.__name__,
            "step_runner": self.step_runner.__class__.__name__,
            "chain_runner": self.chain_runner.__class__.__name__,
            "orchestrator": self.orchestrator.__class__.__name__,
        }


def build_saber_runtime(
    config: SaberConfig | None = None,
    *,
    storage_connection: StorageConnection | None = None,
    tool_registry: ToolRegistry | None = None,
    parser_registry: ParserRegistry | None = None,
    sandbox: Sandbox | None = None,
) -> SaberRuntime:
    """Build SABER runtime from config."""

    runtime_config = config or SaberConfig.from_env()
    runtime_config.ensure_directories()

    connection = storage_connection or StorageConnection(runtime_config.db_path)
    connection.initialize()

    session_store = SessionStore(connection)
    evidence_index = EvidenceIndex(connection)
    finding_store = FindingStore(connection)
    graph_store = GraphStore(connection)

    tools = tool_registry or build_default_registry()
    parsers = parser_registry or build_default_parser_registry()
    tool_catalog = ToolCatalog.from_registry(tools)
    llm_client = LlmClient(runtime_config.llm_config)
    runtime_sandbox = sandbox or _build_sandbox(runtime_config)

    result_processor = ResultProcessor(
        evidence_index=evidence_index,
        finding_store=finding_store,
        graph_store=graph_store,
        parser_registry=parsers,
        evidence_root=runtime_config.evidence_dir,
    )

    agents = build_default_agents(tool_registry=tools)
    if not agents:
        raise RuntimeError("No SABER agents could be initialized.")

    step_runner = StepRunner(
        agents=agents,
        tool_registry=tools,
        sandbox=runtime_sandbox,
    )
    chain_runner = ChainRunner(max_chain_depth=runtime_config.max_chain_depth)

    from saber.agents.deciders.deterministic import DeterministicDecider
    from saber.agents.deciders.llm import LlmDecider
    from saber.core.state_merger import StateMerger
    from saber.core.state_summary import StateSummarizer
    from saber.orchestration.action_executor import ActionExecutor
    from saber.orchestration.mission_loop import MissionLoop
    from saber.orchestration.risk_gate import RiskGate
    from saber.orchestration.stop_conditions import StopEvaluator
    from saber.storage.mission_state_store import MissionStateStore

    if runtime_config.agent_mode == "llm" and llm_client is not None and llm_client.enabled:
        decider = LlmDecider(llm_client=llm_client, tool_catalog=tool_catalog)
    else:
        decider = DeterministicDecider()

    mission_loop = MissionLoop(
        decider=decider,
        summarizer=StateSummarizer(),
        risk_gate=RiskGate(tool_catalog=tool_catalog),
        stop_evaluator=StopEvaluator(max_steps=runtime_config.max_steps),
        executor=ActionExecutor(agents=agents, tool_registry=tools, sandbox=runtime_sandbox),
        merger=StateMerger(),
        state_store=MissionStateStore(connection),
        result_processor=result_processor,
        session_store=session_store,
        max_steps=runtime_config.max_steps,
    )

    orchestrator = MissionOrchestrator(
        agents=agents,
        tool_registry=tools,
        sandbox=runtime_sandbox,
        step_runner=step_runner,
        chain_runner=chain_runner,
        result_processor=result_processor,
        reports_dir=runtime_config.reports_dir,
        max_steps=runtime_config.max_steps,
        mission_loop=mission_loop,
    )

    return SaberRuntime(
        config=runtime_config,
        storage_connection=connection,
        session_store=session_store,
        evidence_index=evidence_index,
        finding_store=finding_store,
        graph_store=graph_store,
        tool_registry=tools,
        parser_registry=parsers,
        tool_catalog=tool_catalog,
        llm_client=llm_client,
        result_processor=result_processor,
        sandbox=runtime_sandbox,
        agents=agents,
        step_runner=step_runner,
        chain_runner=chain_runner,
        orchestrator=orchestrator,
    )


def build_default_agents(tool_registry: ToolRegistry) -> dict[str, Any]:
    """Build default agent instances.

    Agent constructors have shifted during development, so this helper is
    intentionally tolerant. If a class requires extra arguments, the runtime
    skips it instead of failing completely.
    """

    agent_classes = {
        "planner_agent": PlannerAgent,
        "recon_agent": ReconAgent,
        "network_agent": NetworkAgent,
        "web_agent": WebAgent,
        "exploit_agent": ExploitAgent,
        "post_exploit_agent": PostExploitAgent,
        "lateral_movement_agent": LateralMovementAgent,
        "reverse_engineer_agent": ReverseEngineerAgent,
        "reporter_agent": ReporterAgent,
    }

    agents: dict[str, Any] = {}

    for name, cls in agent_classes.items():
        agent = _instantiate_agent(cls, tool_registry=tool_registry)
        if agent is not None:
            agents[name] = agent

    return agents



def _build_sandbox(config: SaberConfig) -> Sandbox:
    """Build sandbox dependencies."""

    evidence_store = EvidenceStore(config.evidence_dir)
    backend = config.sandbox_backend.strip().lower()

    if backend == "docker":
        runner = DockerSubprocessRunner(
            image=config.sandbox_image,
            default_timeout_seconds=config.default_timeout_seconds,
            network=config.docker_network,
            user=config.docker_user,
        )
        return Sandbox(evidence_store=evidence_store, runner=runner)

    if backend == "local":
        runner = LocalSubprocessRunner(default_timeout_seconds=config.default_timeout_seconds)
        return Sandbox(evidence_store=evidence_store, runner=runner)

    raise ValueError(f"Unsupported SABER_SANDBOX_BACKEND: {config.sandbox_backend}")


@dataclass(frozen=True)
class LocalRunnerResult:
    """Local command runner result."""

    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LocalSubprocessRunner:
    """Minimal safe local sandbox runner.

    Security notes:
    - Uses subprocess.run with shell=False.
    - Requires command to be a list/tuple of args.
    - Rejects empty commands.
    - Does not use user input as a shell command.
    """

    default_timeout_seconds: int = 300

    def run(self, command: list[str], **kwargs: Any) -> LocalRunnerResult:
        """Run one command locally."""

        if not isinstance(command, list | tuple):
            raise TypeError("command must be a list or tuple of arguments")
        if not command:
            raise ValueError("command cannot be empty")
        if any(not isinstance(part, str) or not part for part in command):
            raise ValueError("all command parts must be non-empty strings")

        timeout_seconds = kwargs.get("timeout_seconds") or self.default_timeout_seconds
        working_directory = kwargs.get("working_directory")
        environment = kwargs.get("environment") or None

        completed = subprocess.run(
            list(command),
            cwd=working_directory,
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )

        return LocalRunnerResult(
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            return_code=int(completed.returncode),
            metadata={
                "runner": "local_subprocess",
                "timeout_seconds": timeout_seconds,
                "working_directory": working_directory,
            },
        )


def _instantiate_agent(cls: type[Any], tool_registry: ToolRegistry) -> Any | None:
    """Instantiate an agent with tolerant constructor handling."""

    attempts = (
        {"tool_registry": tool_registry},
        {"registry": tool_registry},
        {},
    )

    for kwargs in attempts:
        try:
            return cls(**kwargs)
        except TypeError:
            continue

    return None


def _env_csv(name: str) -> tuple[str, ...]:
    """Read comma-separated env var."""

    value = os.environ.get(name, "")
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _env_bool(name: str, default: bool) -> bool:
    """Read boolean env var."""

    value = os.environ.get(name)
    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "y", "on"}
