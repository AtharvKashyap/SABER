"""SABER command-line interface."""

from __future__ import annotations

import click

from saber.ui.cli.doctor import doctor_command
from saber.ui.cli.sandbox_commands import sandbox_group


@click.group()
@click.version_option(version="0.1.0", prog_name="saber")
def main() -> None:
    """SABER - Scoped Automated Breach, Exploitation & Reporting."""


main.add_command(doctor_command)
main.add_command(sandbox_group)


if __name__ == "__main__":
    main()
