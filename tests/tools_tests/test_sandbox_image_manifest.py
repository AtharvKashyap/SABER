"""Static audit: does the sandbox image actually provide what the contracts invoke?

Every migrated tool now declares a CONTRACT, and its parser is tested against a
fixture — but a contract is a promise about a command that must EXIST at runtime.
If `docker/Dockerfile.sandbox` does not install the executable, the decider can
choose the action, the risk gate can allow it, and it still dies with
"command not found" mid-mission. Fixture tests cannot catch that.

This test derives the required executable for every declared action straight from
`build_command(...)[0]`, so it cannot drift from the contracts, and asserts the
set of executables the image does NOT provide is EXACTLY the documented gap set.
Exact equality matters in both directions: a newly-broken tool fails, and so does
a tool that was fixed in the Dockerfile without being removed from the gap list.

LIMITS — read before trusting this:
- The package->binary map below is STATIC and best-effort. It encodes what Kali
  packages are expected to provide; it does not run the image.
- `tests/e2e_tests/test_image_manifest.py` (Docker-gated) is the ground truth. This
  test is the cheap CI signal that runs without Docker.
"""

from __future__ import annotations

import re
from pathlib import Path

from saber.models.target import Target, TargetType
from saber.tools.registry import build_default_registry

_DOCKERFILE = Path("docker/Dockerfile.sandbox")

# Always present from the base image / the python layer.
#
# "python" is deliberately NOT here. Kali ships python3 with no `python` alias and
# the Dockerfile never installs python-is-python3, so asserting it exists was a false
# premise that made this gate green while the real image fails. Keep this set as small
# as possible: every entry is an unverified assumption, and the Docker-gated
# tests/e2e_tests/test_image_manifest.py is the only ground truth.
_BASE_PROVIDED = {"bash", "find", "python3", "sh"}

# Windows-only executables. The Linux sandbox cannot run these; the wrappers still
# carry contracts so the decider can reason about them for a Windows foothold, but
# the image is not expected to provide them.
_WINDOWS_ONLY = {"cmd.exe", "mimikatz.exe", "winPEASx64.exe"}

# What each apt package in Dockerfile.sandbox is expected to put on PATH.
_PACKAGE_BINARIES: dict[str, set[str]] = {
    "nmap": {"nmap"},
    "masscan": {"masscan"},
    "amass": {"amass"},
    "subfinder": {"subfinder"},
    "theharvester": {"theHarvester"},
    "dnsrecon": {"dnsrecon"},
    "whatweb": {"whatweb"},
    "feroxbuster": {"feroxbuster"},
    "nuclei": {"nuclei"},
    "sqlmap": {"sqlmap"},
    "nikto": {"nikto"},
    "zaproxy": {"zaproxy", "zap.sh"},
    "enum4linux-ng": {"enum4linux-ng"},
    "snmp": {"snmpwalk", "snmpget"},
    "responder": {"responder"},
    "bettercap": {"bettercap"},
    "metasploit-framework": {"msfconsole", "msfvenom"},
    "exploitdb": {"searchsploit"},
    "hashcat": {"hashcat"},
    "john": {"john"},
    "bloodhound.py": {"bloodhound-python"},
    "crackmapexec": {"crackmapexec", "cme"},
    "netexec": {"nxc", "netexec"},
    # Kali prefixes every impacket entrypoint and drops the .py suffix, e.g.
    # /usr/bin/impacket-GetADUsers. Verified against the built image — the wrapper
    # originally invoked "GetADUsers.py", which does not exist on PATH.
    "impacket-scripts": {
        "impacket-GetADUsers",
        "impacket-GetNPUsers",
        "impacket-GetUserSPNs",
        "impacket-psexec",
        "impacket-secretsdump",
    },
    "coreutils": _BASE_PROVIDED,
    # F7.2 additions.
    "binutils": {"strings", "objdump", "readelf"},
    "file": {"file"},
    "checksec": {"checksec"},
    "radare2": {"r2", "radare2"},
    "gdb": {"gdb"},
    "python3-pwntools": {"pwn"},
    "tshark": {"tshark"},
    "enum4linux": {"enum4linux"},
}

# Executables installed by a non-apt step in the Dockerfile (release download).
_DOWNLOADED_BINARIES = {"chisel"}

# Executables a contract invokes that the image deliberately does NOT provide.
# Each entry needs a documented reason — this is not a TODO list, it is the
# recorded decision. See the "deliberately NOT installed" note in the Dockerfile.
_KNOWN_GAPS: set[str] = {
    # ~1GB JDK+Ghidra install; kept out of the default image for size.
    "analyzeHeadless",
    # Needs a provisioned scanner service + feed sync; does not belong in an
    # ephemeral per-action sandbox.
    "openvas-cli",
    # zaproxy ships the daemon/GUI; these helper entrypoints ship separately and
    # the wrapper's HTTP-API path is what the mission actually uses.
    "zap-baseline.py",
    "zap-cli",
}


def _dockerfile_packages() -> set[str]:
    """Return the apt packages the sandbox Dockerfile installs."""

    text = _DOCKERFILE.read_text()
    packages: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip().rstrip("\\").strip()
        # Package continuation lines are bare tokens like "nmap" or "bloodhound.py".
        if re.fullmatch(r"[a-z0-9][a-z0-9.+-]*", stripped):
            packages.add(stripped)
    return packages


def _provided_executables() -> set[str]:
    """Return every executable the image is expected to provide."""

    provided = set(_BASE_PROVIDED) | set(_DOWNLOADED_BINARIES)
    for package in _dockerfile_packages():
        provided |= _PACKAGE_BINARIES.get(package, set())
    return provided


def _required_executables() -> dict[str, set[str]]:
    """Map tool name -> executables its declared actions actually invoke."""

    registry = build_default_registry()
    target = Target(type=TargetType.IP, value="127.0.0.1")
    required: dict[str, set[str]] = {}

    for name in sorted({entry.name for entry in registry._entries.values()}):
        entry = registry.get(name)
        contract = entry.load_contract()
        if contract is None:
            continue
        wrapper = entry.load_class()(sandbox=None)
        executables: set[str] = set()
        for action in contract.actions:
            command = wrapper.build_command(target, action=action.action, **action.example_args)
            if command.command:
                executables.add(command.command[0])
        if executables:
            required[name] = executables
    return required


def test_dockerfile_package_list_is_readable():
    packages = _dockerfile_packages()
    assert "nmap" in packages, "failed to parse the Dockerfile apt package list"
    assert "metasploit-framework" in packages


def test_missing_executables_match_the_documented_gap_set_exactly():
    """The image gap must be exactly what we have documented — no more, no less."""

    required = _required_executables()
    all_required = {exe for exes in required.values() for exe in exes}
    provided = _provided_executables()

    missing = all_required - provided - _WINDOWS_ONLY

    unexpected = missing - _KNOWN_GAPS
    assert not unexpected, (
        f"{sorted(unexpected)} are invoked by a contract but are not installed in "
        f"docker/Dockerfile.sandbox and are not in _KNOWN_GAPS. Either add the package "
        f"to the image or document the gap."
    )

    fixed = _KNOWN_GAPS - missing
    assert not fixed, (
        f"{sorted(fixed)} are now provided by the image but still listed in "
        f"_KNOWN_GAPS. Remove them from the gap set."
    )


def test_every_contract_bearing_tool_resolves_an_executable():
    """A contract whose command is empty would be unrunnable."""

    for tool, executables in _required_executables().items():
        assert executables, f"{tool} declared actions but resolved no executable"


def test_windows_only_tools_are_not_counted_as_image_gaps():
    """mimikatz/winPEAS are contracted for Windows footholds, not the Linux sandbox."""

    required = _required_executables()
    assert _WINDOWS_ONLY & {exe for exes in required.values() for exe in exes}
    assert not _WINDOWS_ONLY & _KNOWN_GAPS
