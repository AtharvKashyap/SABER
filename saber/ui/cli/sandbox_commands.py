"""Docker sandbox commands for SABER."""

from __future__ import annotations

import click

from saber.core.docker_runner import (
    build_sandbox,
    docker_available,
    docker_compose_version,
    docker_info,
    image_exists,
    run_sandbox_shell,
    sandbox_image_name,
)


def _require_docker() -> None:
    if not docker_available():
        raise click.ClickException(
            "Docker CLI was not found. Install Docker Desktop or Docker Engine first."
        )

    info = docker_info()
    if not info.ok:
        raise click.ClickException(
            "Docker is installed, but the daemon/engine is not reachable. "
            "Start Docker Desktop or the Docker service."
        )

    compose = docker_compose_version()
    if not compose.ok:
        raise click.ClickException(
            "Docker Compose plugin is unavailable. SABER requires 'docker compose'."
        )


@click.group("sandbox")
def sandbox_group() -> None:
    """Build and run the SABER Kali sandbox."""


@sandbox_group.command("build")
def sandbox_build_command() -> None:
    """Build the SABER Kali sandbox image."""
    _require_docker()

    click.echo(f"Building sandbox image: {sandbox_image_name()}")
    result = build_sandbox()

    if result.stdout:
        click.echo(result.stdout)

    if not result.ok:
        if result.stderr:
            click.echo(result.stderr, err=True)
        raise click.ClickException("Sandbox image build failed.")

    click.echo(click.style("Sandbox image build complete.", fg="green"))


@sandbox_group.command("status")
def sandbox_status_command() -> None:
    """Check whether the SABER sandbox image exists."""
    _require_docker()

    if image_exists():
        click.echo(click.style(f"Sandbox image exists: {sandbox_image_name()}", fg="green"))
    else:
        click.echo(click.style(f"Sandbox image missing: {sandbox_image_name()}", fg="yellow"))
        click.echo("Build it with:")
        click.echo(click.style("  python -m saber sandbox build", fg="cyan"))


@sandbox_group.command("shell")
def sandbox_shell_command() -> None:
    """Open an interactive shell inside the SABER sandbox."""
    _require_docker()

    if not image_exists():
        raise click.ClickException(
            "Sandbox image is missing. Run: python -m saber sandbox build"
        )

    raise SystemExit(run_sandbox_shell())


@sandbox_group.command("run")
def sandbox_run_command() -> None:
    """Alias for 'sandbox shell'."""
    _require_docker()

    if not image_exists():
        raise click.ClickException(
            "Sandbox image is missing. Run: python -m saber sandbox build"
        )

    raise SystemExit(run_sandbox_shell())
