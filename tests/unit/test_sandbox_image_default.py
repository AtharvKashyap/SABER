"""The sandbox image name must be defined in exactly one place.

It was duplicated across runtime.py, run_command.py, scripts/launch_saber.py, the
Makefile, .env.example and eight e2e tests. Two different values ended up in the
tree at once (`ghcr.io/...:kali-last-release` and `saber-sandbox:f7`), so `make
e2e` on a fresh clone silently ran against a published image missing six
executables that tool contracts invoke — checksec, radare2, gdb, pwntools,
chisel and enum4linux — and failed with an assertion about checksec rather than
"your image is out of date".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from saber.core.docker_runner import DEFAULT_SHARED_IMAGE

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_the_default_is_the_locally_built_tag() -> None:
    """`make sandbox-build` must produce exactly what the code defaults to."""

    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    match = re.search(r"^SANDBOX_TAG \?= (\S+)", makefile, re.M)

    assert match, "Makefile no longer defines SANDBOX_TAG"
    assert match.group(1) == DEFAULT_SHARED_IMAGE


def test_env_example_matches_the_code_default() -> None:
    """An operator copying .env.example must get the working image."""

    env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    match = re.search(r"^SABER_SANDBOX_IMAGE=(\S+)", env_example, re.M)

    assert match, ".env.example no longer sets SABER_SANDBOX_IMAGE"
    assert match.group(1) == DEFAULT_SHARED_IMAGE


def test_the_launcher_stays_in_step() -> None:
    """launch_saber.py cannot import saber (it is what checks the venv), so it
    carries its own literal. That literal must not drift."""

    launcher = (REPO_ROOT / "scripts/launch_saber.py").read_text(encoding="utf-8")
    match = re.search(r'^DEFAULT_IMAGE = "([^"]+)"', launcher, re.M)

    assert match, "launch_saber.py no longer defines DEFAULT_IMAGE"
    assert match.group(1) == DEFAULT_SHARED_IMAGE


@pytest.mark.parametrize(
    "relative",
    [
        "saber/core/runtime.py",
        "saber/ui/cli/run_command.py",
        "tests/e2e_tests",
    ],
)
def test_nothing_hardcodes_an_image_name_beside_the_constant(relative: str) -> None:
    """Production and e2e code must reference DEFAULT_SHARED_IMAGE, not a literal."""

    target = REPO_ROOT / relative
    files = sorted(target.rglob("*.py")) if target.is_dir() else [target]

    offenders: list[str] = []
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "saber-sandbox" in line and "DEFAULT_SHARED_IMAGE" not in line:
                if line.lstrip().startswith("#"):
                    continue
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}")

    assert not offenders, "hardcoded sandbox image name:\n" + "\n".join(offenders)
