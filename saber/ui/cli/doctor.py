"""Environment checks for SABER."""

from __future__ import annotations

import platform
import sys
from pathlib import Path

import click

from saber.core.docker_runner import (
    docker_available,
    docker_compose_version,
    docker_info,
    image_exists,
    repo_root,
    sandbox_compose_file,
    sandbox_image_name,
)


def _status_line(label: str, ok: bool, detail: str = "") -> None:
    status = click.style("OK", fg="green") if ok else click.style("MISSING", fg="red")
    suffix = f" - {detail}" if detail else ""
    click.echo(f"{label:<30} {status}{suffix}")


@click.command("doctor")
def doctor_command() -> None:
    """Check whether the local machine can run SABER."""
    root = repo_root()

    click.echo(click.style("SABER Doctor", bold=True))
    click.echo(f"Repository root: {root}")
    click.echo(f"Platform: {platform.system()} {platform.release()}")
    click.echo()

    python_ok = sys.version_info >= (3, 11)
    _status_line(
        "Python 3.11+",
        python_ok,
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )

    docker_ok = docker_available()
    _status_line("Docker CLI", docker_ok)

    daemon_ok = False
    compose_ok = False

    if docker_ok:
        daemon_result = docker_info()
        daemon_ok = daemon_result.ok
        _status_line("Docker daemon", daemon_ok)

        compose_result = docker_compose_version()
        compose_ok = compose_result.ok
        detail = compose_result.stdout.splitlines()[0] if compose_result.stdout else ""
        _status_line("Docker Compose plugin", compose_ok, detail)
    else:
        _status_line("Docker daemon", False, "Docker CLI not found")
        _status_line("Docker Compose plugin", False, "Docker CLI not found")

    compose_file = sandbox_compose_file()
    _status_line("Sandbox compose file", compose_file.exists(), str(compose_file))

    dockerfile = root / "docker" / "Dockerfile.sandbox"
    _status_line("Sandbox Dockerfile", dockerfile.exists(), str(dockerfile))

    env_example = root / ".env.example"
    env_file = root / ".env"
    env_ok = env_file.exists() or env_example.exists()
    detail = ".env exists" if env_file.exists() else ".env.example exists" if env_example.exists() else ""
    _status_line("Environment file", env_ok, detail)

    requirements = root / "requirements.txt"
    _status_line("requirements.txt", requirements.exists(), str(requirements))

    image_ok = docker_ok and daemon_ok and image_exists()
    _status_line("Sandbox image", image_ok, sandbox_image_name())

    click.echo()

    if not python_ok:
        click.echo(click.style("Python 3.11 or newer is required.", fg="red"))

    if not docker_ok:
        click.echo(click.style("Docker was not found on PATH.", fg="red"))
        click.echo("Install Docker Desktop on macOS/Windows or Docker Engine on Linux.")

    if docker_ok and not daemon_ok:
        click.echo(click.style("Docker is installed, but the engine is not reachable.", fg="red"))
        click.echo("Start Docker Desktop or the Docker service, then rerun this command.")

    if docker_ok and daemon_ok and not compose_ok:
        click.echo(click.style("Docker Compose plugin is missing.", fg="red"))
        click.echo("Update Docker Desktop or install the Docker Compose plugin.")

    if docker_ok and daemon_ok and compose_ok and not image_ok:
        click.echo("Next step:")
        click.echo(click.style("  python -m saber sandbox build", fg="cyan"))

    if python_ok and docker_ok and daemon_ok and compose_ok:
        click.echo(click.style("SABER environment checks completed.", fg="green"))
