"""Cross-platform Docker command helpers and Docker runner for SABER."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any


DEFAULT_SHARED_IMAGE = "ghcr.io/atharvkashyap/saber-sandbox:kali-last-release"
DEFAULT_LOCAL_IMAGE = "saber/sandbox:kali-last-release"
CONTAINER_WORKSPACE = Path("/workspace")


@dataclass(slots=True)
class CommandResult:
    """Result of a local command execution."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        """Return True when command succeeded."""

        return self.returncode == 0


@dataclass(frozen=True)
class DockerRunnerResult:
    """Docker command runner result compatible with SABER Sandbox."""

    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DockerSubprocessRunner:
    """Run SABER tool commands inside the sandbox Docker image.

    Security notes:
    - Uses subprocess.run with shell=False.
    - Requires commands as argument lists.
    - Mounts the repo at /workspace.
    - Maps absolute repo-local host paths into /workspace paths.
    """

    image: str = DEFAULT_SHARED_IMAGE
    default_timeout_seconds: int = 300
    network: str = "host"
    user: str = ""
    repo_dir: Path = field(default_factory=lambda: repo_root())
    cap_add: tuple[str, ...] = ("NET_RAW", "NET_ADMIN")

    def run(self, command: list[str], **kwargs: Any) -> DockerRunnerResult:
        """Run one command inside Docker."""

        self._validate_command(command)

        timeout_seconds = kwargs.get("timeout_seconds") or self.default_timeout_seconds
        working_directory = kwargs.get("working_directory")
        environment = kwargs.get("environment") or {}

        docker_command = self.build_docker_command(
            command=list(command),
            working_directory=working_directory,
            environment=environment,
        )

        completed = subprocess.run(
            docker_command,
            cwd=str(self.repo_dir),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )

        return DockerRunnerResult(
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            return_code=int(completed.returncode),
            metadata={
                "runner": "docker_subprocess",
                "image": self.image,
                "network": self.network,
                "user": self.user,
                "timeout_seconds": timeout_seconds,
                "working_directory": str(working_directory) if working_directory else None,
                "docker_command": docker_command,
            },
        )

    def build_docker_command(
        self,
        *,
        command: list[str],
        working_directory: str | Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> list[str]:
        """Build docker run command."""

        self._validate_command(command)

        docker_command = [
            "docker",
            "run",
            "--rm",
        ]

        if self.network:
            docker_command.extend(["--network", self.network])

        for capability in self.cap_add:
            if capability:
                docker_command.extend(["--cap-add", capability])

        if self.user:
            docker_command.extend(["--user", self.user])

        docker_command.extend(
            [
                "-v",
                f"{self.repo_dir.resolve()}:{CONTAINER_WORKSPACE}",
                "-w",
                str(self._container_workdir(working_directory)),
            ]
        )

        for key, value in sorted((environment or {}).items()):
            if key and value is not None:
                docker_command.extend(["-e", f"{key}={value}"])

        docker_command.append(self.image)
        docker_command.extend(self._map_command_paths(command))
        return docker_command

    def _container_workdir(self, working_directory: str | Path | None) -> Path:
        """Map host working directory to container working directory."""

        if working_directory is None:
            return CONTAINER_WORKSPACE

        path = Path(working_directory)

        if not path.is_absolute():
            return CONTAINER_WORKSPACE / path

        try:
            relative = path.resolve().relative_to(self.repo_dir.resolve())
        except ValueError:
            return CONTAINER_WORKSPACE

        return CONTAINER_WORKSPACE / relative

    def _map_command_paths(self, command: list[str]) -> list[str]:
        """Map absolute repo-local host paths in command args into container paths."""

        mapped: list[str] = []

        for part in command:
            mapped.append(self._map_one_arg(part))

        return mapped

    def _map_one_arg(self, arg: str) -> str:
        """Map one command argument if it is an absolute path under repo."""

        path = Path(arg)

        if not path.is_absolute():
            return arg

        try:
            relative = path.resolve().relative_to(self.repo_dir.resolve())
        except ValueError:
            return arg

        return str(CONTAINER_WORKSPACE / relative)

    @staticmethod
    def _validate_command(command: list[str]) -> None:
        """Validate command argument list."""

        if not isinstance(command, list | tuple):
            raise TypeError("command must be a list or tuple of arguments")
        if not command:
            raise ValueError("command cannot be empty")
        if any(not isinstance(part, str) or not part for part in command):
            raise ValueError("all command parts must be non-empty strings")


def repo_root() -> Path:
    """Return the repository root based on this file location."""

    return Path(__file__).resolve().parents[2]


def docker_available() -> bool:
    """Return True if the Docker CLI exists on PATH."""

    return shutil.which("docker") is not None


def run_command(command: list[str], *, cwd: Path | None = None) -> CommandResult:
    """Run a command without shell=True and capture output."""

    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
    )
    return CommandResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def docker_info() -> CommandResult:
    """Check whether Docker daemon/engine is reachable."""

    return run_command(["docker", "info"])


def docker_compose_version() -> CommandResult:
    """Check whether the Docker Compose plugin is available."""

    return run_command(["docker", "compose", "version"])


def sandbox_compose_file() -> Path:
    """Return the sandbox Docker Compose file path."""

    return repo_root() / "docker" / "docker-compose.sandbox.yml"


def sandbox_image_name() -> str:
    """Return the expected sandbox image name."""

    return os.getenv("SABER_SANDBOX_IMAGE", DEFAULT_SHARED_IMAGE)


def build_sandbox() -> CommandResult:
    """Build the SABER sandbox image using Dockerfile directly."""

    root = repo_root()
    image = os.getenv("SABER_SANDBOX_IMAGE", DEFAULT_LOCAL_IMAGE)

    if image.startswith("ghcr.io/") or image.startswith("docker.io/"):
        image = DEFAULT_LOCAL_IMAGE

    return run_command(
        [
            "docker",
            "build",
            "-f",
            str(root / "docker" / "Dockerfile.sandbox"),
            "-t",
            image,
            ".",
        ],
        cwd=root,
    )


def run_sandbox_shell() -> int:
    """Start an interactive shell inside the SABER sandbox."""

    root = repo_root()
    image = sandbox_image_name()

    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-it",
            "--network",
            os.getenv("SABER_DOCKER_NETWORK", "host"),
            "-v",
            f"{root.resolve()}:{CONTAINER_WORKSPACE}",
            "-w",
            str(CONTAINER_WORKSPACE),
            image,
            "bash",
        ],
        cwd=str(root),
        check=False,
    )
    return completed.returncode


def image_exists() -> bool:
    """Return True if the SABER sandbox image exists locally."""

    result = run_command(
        [
            "docker",
            "image",
            "inspect",
            sandbox_image_name(),
        ]
    )
    return result.ok
