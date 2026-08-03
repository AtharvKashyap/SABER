"""The image manifest must be derived from contracts, and the check must ask the image.

`sandbox check` used to call shutil.which() on the HOST. Agents never run on the
host — every tool executes inside the sandbox container — so on a normal
workstation it reported every tool "not found" and told the operator nothing. That
blind spot is why a published image missing six contracted executables
(checksec, radare2, gdb, pwntools, chisel, enum4linux) went unnoticed until a
mission tried to use one.
"""

from __future__ import annotations

from unittest.mock import patch

from saber.tools.image_manifest import (
    NOT_EXPECTED,
    expected_executables,
    missing_in_image,
    required_executables,
)
from saber.ui.cli.sandbox_commands import SandboxCommands


def test_executables_are_derived_from_the_contracts() -> None:
    """Not a hand-maintained list: the contracts build real commands."""

    required = required_executables()

    assert required["nmap"] == {"nmap"}
    assert "sqlmap" in required["sqlmap"]
    assert len(required) >= 30


def test_windows_and_path_invoked_binaries_are_not_expected_on_linux() -> None:
    """Windows payloads staged for upload must not be demanded of a Linux image."""

    expected = set(expected_executables())

    assert not expected & NOT_EXPECTED
    assert "mimikatz.exe" not in expected
    assert "nmap" in expected


def test_a_complete_image_reports_nothing_missing() -> None:
    """Every name echoed back by the probe is a miss; silence means complete."""

    completed = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    with (
        patch("saber.tools.image_manifest.shutil.which", return_value="/usr/bin/docker"),
        patch("saber.tools.image_manifest.subprocess.run", return_value=completed),
    ):
        assert missing_in_image("img") == []


def test_missing_executables_are_reported() -> None:
    completed = type("R", (), {"returncode": 0, "stdout": "checksec\nradare2\n", "stderr": ""})()
    with (
        patch("saber.tools.image_manifest.shutil.which", return_value="/usr/bin/docker"),
        patch("saber.tools.image_manifest.subprocess.run", return_value=completed),
    ):
        assert missing_in_image("img", ["checksec", "radare2", "nmap"]) == ["checksec", "radare2"]


def test_output_naming_something_we_did_not_ask_about_is_ignored() -> None:
    """Only names we probed for count, so stray image output cannot invent a miss."""

    completed = type("R", (), {"returncode": 0, "stdout": "checksec\nMOTD junk\n", "stderr": ""})()
    with (
        patch("saber.tools.image_manifest.shutil.which", return_value="/usr/bin/docker"),
        patch("saber.tools.image_manifest.subprocess.run", return_value=completed),
    ):
        assert missing_in_image("img", ["checksec", "nmap"]) == ["checksec"]


def test_an_unrunnable_image_raises_rather_than_reporting_complete() -> None:
    """Failing open here would report a broken image as healthy."""

    failed = type("R", (), {"returncode": 125, "stdout": "", "stderr": "no such image"})()
    with (
        patch("saber.tools.image_manifest.shutil.which", return_value="/usr/bin/docker"),
        patch("saber.tools.image_manifest.subprocess.run", return_value=failed),
    ):
        try:
            missing_in_image("nope", ["nmap"])
        except RuntimeError as exc:
            assert "no such image" in str(exc)
        else:
            raise AssertionError("a broken image must not report as complete")


def test_check_reports_an_incomplete_image_as_a_failure() -> None:
    with (
        patch("saber.ui.cli.sandbox_commands.shutil.which", return_value="/usr/bin/docker"),
        patch(
            "saber.ui.cli.sandbox_commands.missing_in_image",
            return_value=["checksec", "radare2"],
        ),
    ):
        check = SandboxCommands().check(image="img")

    assert check.image_complete is False
    assert check.missing_executables == ["checksec", "radare2"]

    text = SandboxCommands.format_check(check)
    assert "FAIL" in text
    assert "checksec" in text
    assert "make sandbox-build" in text


def test_check_reports_a_complete_image_as_healthy() -> None:
    with (
        patch("saber.ui.cli.sandbox_commands.shutil.which", return_value="/usr/bin/docker"),
        patch("saber.ui.cli.sandbox_commands.missing_in_image", return_value=[]),
    ):
        check = SandboxCommands().check(image="img")

    assert check.image_complete is True
    assert check.missing_executables == []
    assert "FAIL" not in SandboxCommands.format_check(check)


def test_check_without_docker_does_not_claim_the_image_is_fine() -> None:
    with patch("saber.ui.cli.sandbox_commands.shutil.which", return_value=None):
        check = SandboxCommands().check(image="img")

    assert check.docker_available is False
    assert check.image_complete is None


def test_check_surfaces_an_inspection_error_with_build_guidance() -> None:
    with (
        patch("saber.ui.cli.sandbox_commands.shutil.which", return_value="/usr/bin/docker"),
        patch(
            "saber.ui.cli.sandbox_commands.missing_in_image",
            side_effect=RuntimeError("could not run image img: not found locally"),
        ),
    ):
        check = SandboxCommands().check(image="img")

    text = SandboxCommands.format_check(check)
    assert check.image_complete is None
    assert "not found locally" in text
    assert "make sandbox-build" in text
