"""Golden build_command test for the feroxbuster CONTRACT."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.web.feroxbuster import FeroxbusterWrapper


def test_directory_bruteforce_command_from_example_args():
    wrapper = FeroxbusterWrapper(sandbox=None)  # build_command does not touch sandbox
    target = Target(type=TargetType.IP, value="127.0.0.1")

    cmd = wrapper.build_command(
        target,
        action="directory_bruteforce",
        url="http://127.0.0.1/",
        wordlist="wordlists/common.txt",
    )

    assert cmd.command == [
        "feroxbuster",
        "-u",
        "http://127.0.0.1/",
        "-w",
        "wordlists/common.txt",
        "--json",
        "-t",
        "50",
    ]
    assert cmd.action == "directory_bruteforce"


def test_directory_bruteforce_defaults_wordlist_when_omitted():
    wrapper = FeroxbusterWrapper(sandbox=None)
    target = Target(type=TargetType.IP, value="127.0.0.1")

    cmd = wrapper.build_command(target, action="directory_bruteforce", url="http://127.0.0.1/")

    assert cmd.command == [
        "feroxbuster",
        "-u",
        "http://127.0.0.1/",
        "-w",
        "wordlists/common.txt",
        "--json",
        "-t",
        "50",
    ]
