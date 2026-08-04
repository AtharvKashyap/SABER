"""How a container reaches the test host, per platform.

The E2E tests that stand up a service on the host used to hardcode
``host.docker.internal``. That is a Docker Desktop feature, so those tests passed
on macOS and failed on Linux CI with "no address for host.docker.internal" — the
same macOS-versus-Linux class of bug as the sandbox's non-root user.

These are unit tests on purpose. The E2E tests they support only run behind
SABER_RUN_DOCKER_E2E, but the tests.yml matrix runs Linux, macOS and Windows, so
this is where the per-platform branches actually get exercised everywhere.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from tests.support.docker_host import (
    DOCKER_DESKTOP_HOST,
    sandbox_host_address,
    sandbox_host_url,
)


@pytest.mark.parametrize("system", ["Darwin", "Windows"])
@pytest.mark.parametrize("network", ["host", "bridge", "saber-lab", ""])
def test_docker_desktop_always_uses_the_name_it_publishes(system, network) -> None:
    """Desktop publishes host.docker.internal, and it is the only route that works.

    Under --network host on Desktop the container joins the Linux VM's namespace,
    not the host's, so loopback reaches the VM instead of the machine.
    """

    with patch("tests.support.docker_host.platform.system", return_value=system):
        assert sandbox_host_address(network) == DOCKER_DESKTOP_HOST


@pytest.mark.parametrize("network", ["host", ""])
def test_linux_host_networking_uses_loopback(network) -> None:
    """Under host networking the container shares this machine's namespace."""

    with patch("tests.support.docker_host.platform.system", return_value="Linux"):
        assert sandbox_host_address(network) == "127.0.0.1"


def test_linux_bridge_networking_uses_the_network_gateway() -> None:
    inspect = type(
        "R",
        (),
        {
            "returncode": 0,
            "stdout": '[{"IPAM": {"Config": [{"Gateway": "172.17.0.1"}]}}]',
            "stderr": "",
        },
    )()
    with (
        patch("tests.support.docker_host.platform.system", return_value="Linux"),
        patch("tests.support.docker_host.shutil.which", return_value="/usr/bin/docker"),
        patch("tests.support.docker_host.subprocess.run", return_value=inspect),
    ):
        assert sandbox_host_address("bridge") == "172.17.0.1"


def test_an_undeterminable_route_returns_none_so_callers_can_skip() -> None:
    """An unreachable host is an environment limit, not a SABER defect.

    Returning None lets the E2E test skip with a clear reason instead of failing
    in a way that looks like the product is broken.
    """

    missing = type("R", (), {"returncode": 1, "stdout": "", "stderr": "No such network"})()
    with (
        patch("tests.support.docker_host.platform.system", return_value="Linux"),
        patch("tests.support.docker_host.shutil.which", return_value="/usr/bin/docker"),
        patch("tests.support.docker_host.subprocess.run", return_value=missing),
    ):
        assert sandbox_host_address("does-not-exist") is None


def test_no_docker_binary_returns_none_rather_than_guessing() -> None:
    with (
        patch("tests.support.docker_host.platform.system", return_value="Linux"),
        patch("tests.support.docker_host.shutil.which", return_value=None),
    ):
        assert sandbox_host_address("bridge") is None


def test_malformed_inspect_output_returns_none() -> None:
    """A docker version that changes its JSON shape must not yield a bogus address."""

    junk = type("R", (), {"returncode": 0, "stdout": "not json", "stderr": ""})()
    with (
        patch("tests.support.docker_host.platform.system", return_value="Linux"),
        patch("tests.support.docker_host.shutil.which", return_value="/usr/bin/docker"),
        patch("tests.support.docker_host.subprocess.run", return_value=junk),
    ):
        assert sandbox_host_address("bridge") is None


def test_url_helper_composes_scheme_host_and_port() -> None:
    with patch("tests.support.docker_host.platform.system", return_value="Linux"):
        assert sandbox_host_url(8080, "host") == "http://127.0.0.1:8080"
        assert sandbox_host_url(443, "host", scheme="https") == "https://127.0.0.1:443"


def test_url_helper_propagates_none() -> None:
    with (
        patch("tests.support.docker_host.platform.system", return_value="Linux"),
        patch("tests.support.docker_host.shutil.which", return_value=None),
    ):
        assert sandbox_host_url(8080, "bridge") is None
