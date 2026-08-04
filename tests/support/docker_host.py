"""How a sandbox container reaches the machine running the tests.

Some E2E tests stand up a service on the host and point a real tool at it. The
address to use is not the same on every platform, and getting it wrong fails in a
way that looks like a product defect:

* Docker Desktop (macOS, Windows) publishes ``host.docker.internal`` itself, and
  it is the only route that works there — ``--network host`` puts the container
  in the Linux VM's namespace, not the host's, so loopback reaches the VM.
* Native Docker on Linux does NOT publish that name. A test hardcoding it fails
  with "no address for host.docker.internal", which is exactly how this surfaced
  in CI on ubuntu-latest. Under ``--network host`` the container shares the
  host's own namespace, so plain loopback is correct there.
* Under a bridge or user-defined network on Linux, neither works, so the address
  has to come from the network's gateway.

Overriding ``host.docker.internal`` with ``--add-host host-gateway`` looks like a
tidy fix and is not: on Docker Desktop it replaces the working mapping with an
address nothing is listening on. Measured, not assumed.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess

# Docker Desktop provides this name; native Linux Docker does not.
DOCKER_DESKTOP_HOST = "host.docker.internal"


def _is_docker_desktop_platform() -> bool:
    return platform.system() in {"Darwin", "Windows"}


def _bridge_gateway(network: str) -> str | None:
    """Return the gateway address of a Docker network, or None."""

    if shutil.which("docker") is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, test-support only
            ["docker", "network", "inspect", network],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None

    try:
        configs = json.loads(result.stdout)[0]["IPAM"]["Config"]
    except (IndexError, KeyError, TypeError, ValueError):
        return None

    for config in configs or []:
        gateway = (config or {}).get("Gateway")
        if gateway:
            return str(gateway)
    return None


def sandbox_host_address(network: str = "host") -> str | None:
    """Return the address a sandbox container can use to reach this machine.

    ``network`` is the Docker network the container will run on. Returns None when
    no route can be determined, so callers should skip rather than fail: an
    unreachable host is an environment limitation, not a defect in SABER.
    """

    if _is_docker_desktop_platform():
        return DOCKER_DESKTOP_HOST

    # Linux (and anything else): the container shares this machine's network
    # namespace under host networking, so loopback is the host.
    if network in {"host", ""}:
        return "127.0.0.1"

    return _bridge_gateway(network)


def sandbox_host_url(port: int, network: str = "host", scheme: str = "http") -> str | None:
    """Return a URL for ``port`` on this machine, reachable from the sandbox."""

    address = sandbox_host_address(network)
    if address is None:
        return None
    return f"{scheme}://{address}:{port}"


__all__ = ["DOCKER_DESKTOP_HOST", "sandbox_host_address", "sandbox_host_url"]
