"""The sandbox container must run as root, and here is why that is pinned.

`USER saber` was set in docker/Dockerfile.sandbox for defence in depth. It broke
far more than it protected, and it broke quietly:

* A non-root user does not inherit the container's capabilities, so the
  NET_RAW/NET_ADMIN that DockerSubprocessRunner grants were unusable.
* The Dockerfile already runs `setcap -r` on nmap — needed because Docker Desktop
  refuses to execute binaries carrying file capabilities — so file caps were not
  a fallback either.
* Therefore `nmap -sU`, which the nmap contract declares, plus masscan,
  responder and bettercap could not work at all.
* On Linux the bind-mounted workspace was not writable, because the host
  directory belongs to a different uid than the container user.

None of that failed loudly, and the Docker E2E suite missed it for months because
it pulled a PUBLISHED image that predated the `USER saber` commit and so still ran
as root. These are static checks on the Dockerfile, so they run in normal CI
rather than only under SABER_RUN_DOCKER_E2E.
"""

from __future__ import annotations

import re
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[2] / "docker" / "Dockerfile.sandbox"


def _lines() -> list[str]:
    return DOCKERFILE.read_text(encoding="utf-8").splitlines()


def test_no_user_directive_drops_privileges() -> None:
    """A USER line to anything but root re-breaks the raw-socket tools."""

    offenders = [
        line
        for line in _lines()
        if re.match(r"^\s*USER\s+", line) and not re.match(r"^\s*USER\s+(root|0)\s*$", line)
    ]

    assert not offenders, (
        "the sandbox must run as root or capabilities and workspace writes break:\n"
        + "\n".join(offenders)
    )


def test_the_runner_still_grants_only_the_two_capabilities_it_needs() -> None:
    """Running as root is not a licence to run privileged."""

    from saber.core.docker_runner import DockerSubprocessRunner

    runner = DockerSubprocessRunner(image="img")

    assert set(runner.cap_add) == {"NET_RAW", "NET_ADMIN"}


def test_the_container_is_not_privileged_and_is_removed_after_each_run() -> None:
    """Root inside a disposable, unprivileged container is the intended boundary."""

    from pathlib import Path as _Path

    from saber.core.docker_runner import DockerSubprocessRunner

    runner = DockerSubprocessRunner(image="img", repo_dir=_Path("/tmp"))
    argv = runner.build_docker_command(command=["nmap", "127.0.0.1"])

    assert "--privileged" not in argv
    assert "--rm" in argv
    assert "--cap-add" in argv


def test_nmap_file_capabilities_are_still_removed() -> None:
    """Docker Desktop refuses to exec binaries carrying file caps.

    Removing them is correct — the container's runtime capabilities are what make
    raw sockets work, and those only apply because we now run as root.
    """

    body = DOCKERFILE.read_text(encoding="utf-8")

    assert "setcap -r /usr/lib/nmap/nmap" in body
