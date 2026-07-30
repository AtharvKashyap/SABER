"""Ground truth for the sandbox image: does `which <exe>` actually succeed?

`tests/tools_tests/test_sandbox_image_manifest.py` is the cheap CI proxy — it reads
the Dockerfile and a static package->binary map. This test is the real check: it
runs inside the built image and asks the image itself.

Gated on SABER_RUN_DOCKER_E2E=1 (see `make e2e`) because it needs Docker and a
built sandbox image.

If this disagrees with the static audit, THIS one is right and the static map needs
correcting — a package that does not provide the binary we assumed is exactly the
failure the static map cannot see.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest
from saber.models.target import Target, TargetType
from saber.tools.registry import build_default_registry

pytestmark = pytest.mark.skipif(
    os.environ.get("SABER_RUN_DOCKER_E2E") != "1",
    reason="Docker E2E disabled (set SABER_RUN_DOCKER_E2E=1)",
)

_IMAGE = os.environ.get(
    "SABER_SANDBOX_IMAGE", "ghcr.io/atharvkashyap/saber-sandbox:kali-last-release"
)

# Not expected on PATH in the Linux sandbox — see the Dockerfile's
# "deliberately NOT installed" note and _KNOWN_GAPS in the static audit.
_NOT_EXPECTED = {
    "cmd.exe",
    "mimikatz.exe",
    "winPEASx64.exe",
    "analyzeHeadless",
    "openvas-cli",
    "zap-baseline.py",
    "zap-cli",
}


def _required_executables() -> dict[str, set[str]]:
    """Map tool -> executables its declared actions invoke, from the contracts."""

    registry = build_default_registry()
    target = Target(type=TargetType.IP, value="127.0.0.1")
    required: dict[str, set[str]] = {}

    for name in sorted({entry.name for entry in registry._entries.values()}):
        entry = registry.get(name)
        contract = entry.load_contract()
        if contract is None:
            continue
        wrapper = entry.load_class()(sandbox=None)
        executables = set()
        for action in contract.actions:
            command = wrapper.build_command(target, action=action.action, **action.example_args)
            if command.command:
                executables.add(command.command[0])
        required[name] = executables
    return required


def _expected_executables() -> list[str]:
    required = _required_executables()
    everything = {exe for exes in required.values() for exe in exes}
    return sorted(everything - _NOT_EXPECTED)


@pytest.fixture(scope="module")
def docker_available() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker binary not available on PATH")


@pytest.mark.parametrize("executable", _expected_executables())
def test_executable_is_present_in_sandbox_image(executable: str, docker_available: None) -> None:
    """Every executable a contract invokes must resolve inside the image."""

    result = subprocess.run(  # noqa: S603 - fixed argv, test-only Docker invocation
        ["docker", "run", "--rm", "--entrypoint", "sh", _IMAGE, "-lc", f"command -v {executable}"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, (
        f"{executable!r} is invoked by a tool contract but is not on PATH in {_IMAGE}. "
        f"stdout={result.stdout.strip()!r} stderr={result.stderr.strip()!r}"
    )


def test_pwntools_is_importable(docker_available: None) -> None:
    """pwntools is a library, not a binary — the F5.X exploit loop imports it."""

    result = subprocess.run(  # noqa: S603 - fixed argv, test-only Docker invocation
        ["docker", "run", "--rm", "--entrypoint", "python3", _IMAGE, "-c", "import pwn"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, (
        f"pwntools is not importable in {_IMAGE}: {result.stderr.strip()!r}"
    )


def test_linpeas_script_is_staged_at_the_contract_default_path(docker_available: None) -> None:
    """The linpeas contract defaults to /opt/peas/linpeas.sh; the image must match."""

    result = subprocess.run(  # noqa: S603 - fixed argv, test-only Docker invocation
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            _IMAGE,
            "-lc",
            "test -r /opt/peas/linpeas.sh",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, "/opt/peas/linpeas.sh is missing from the sandbox image"
