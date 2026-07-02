"""Cross-platform Docker command helpers for SABER."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class CommandResult:
    """Result of a local command execution."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


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
    return "saber/sandbox:kali-last-release"


def build_sandbox() -> CommandResult:
    """Build the SABER sandbox image."""
    root = repo_root()
    compose_file = sandbox_compose_file()
    return run_command(
        ["docker", "compose", "-f", str(compose_file), "build"],
        cwd=root,
    )


def run_sandbox_shell() -> int:
    """Start an interactive shell inside the SABER sandbox."""
    root = repo_root()
    compose_file = sandbox_compose_file()
    completed = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "run", "--rm", "saber-sandbox"],
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