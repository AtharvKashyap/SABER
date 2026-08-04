"""What executables the sandbox image must contain, derived from tool contracts.

The contracts are the only honest source for this: a tool's declared actions build
real commands, and the first token of each is the executable that has to exist in
the image. Hand-maintained lists drift, and drift here is expensive — a published
image missing six binaries let every reverse-engineering and binary-exploitation
action fail while recon and web work carried on looking fine.

Used by the ``sandbox check`` CLI and by the image-manifest E2E test, so both ask
the same question.
"""

from __future__ import annotations

import shutil
import subprocess

from saber.models.target import Target, TargetType
from saber.tools.registry import ToolRegistry, build_default_registry

# Executables that are legitimately absent from a Linux sandbox: Windows binaries
# staged for upload to a target, and headless entry points invoked by full path.
# See the "deliberately NOT installed" note in docker/Dockerfile.sandbox.
NOT_EXPECTED = frozenset(
    {
        "cmd.exe",
        "mimikatz.exe",
        "winPEASx64.exe",
        "analyzeHeadless",
        "openvas-cli",
        "zap-baseline.py",
        "zap-cli",
    }
)


def required_executables(registry: ToolRegistry | None = None) -> dict[str, set[str]]:
    """Map each tool to the executables its declared actions invoke."""

    registry = registry or build_default_registry()
    target = Target(type=TargetType.IP, value="127.0.0.1")
    required: dict[str, set[str]] = {}

    for name in sorted({entry.name for entry in registry.list_entries()}):
        entry = registry.get(name)
        contract = entry.load_contract()
        if contract is None:
            continue
        try:
            wrapper = entry.load_class()(sandbox=None)
        except Exception:  # noqa: BLE001 - an unloadable wrapper is a registry problem
            continue

        executables: set[str] = set()
        for action in contract.actions:
            try:
                command = wrapper.build_command(target, action=action.action, **action.example_args)
            except Exception:  # noqa: BLE001 - a contract example that will not build
                continue
            if command.command:
                executables.add(command.command[0])
        required[name] = executables

    return required


def expected_executables(registry: ToolRegistry | None = None) -> list[str]:
    """Return the sorted executables that must be on PATH inside the image."""

    found: set[str] = set()
    for executables in required_executables(registry).values():
        found.update(executables)
    return sorted(name for name in found if name not in NOT_EXPECTED)


def missing_in_image(image: str, executables: list[str] | None = None) -> list[str]:
    """Return the expected executables that are NOT on PATH inside ``image``.

    Asks the image itself in a single container rather than probing per tool,
    because starting ~37 containers to run ``command -v`` is slow enough that
    nobody runs the check. Returns an empty list when the image is complete.

    Raises:
        RuntimeError: If Docker is unavailable or the image cannot be run.
    """

    names = executables if executables is not None else expected_executables()
    if not names:
        return []

    if shutil.which("docker") is None:
        raise RuntimeError("docker is not on PATH, so the sandbox image cannot be inspected.")

    script = "; ".join(f'command -v {name} >/dev/null 2>&1 || echo {name}' for name in names)
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, names come from contracts
            ["docker", "run", "--rm", "--entrypoint", "sh", image, "-lc", script],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"could not inspect image {image}: {exc}") from exc

    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(
            f"could not run image {image}: {result.stderr.strip() or 'unknown docker error'}"
        )

    reported = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    return sorted(reported & set(names))


__all__ = [
    "NOT_EXPECTED",
    "expected_executables",
    "missing_in_image",
    "required_executables",
]
