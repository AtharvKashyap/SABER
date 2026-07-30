"""Regression guards for defects found in the Workstream F whole-branch review.

Each test here asserts the CORRECT behaviour for a defect the review reported. They
were written to fail first, confirming the finding was real rather than taking the
report at face value.
"""

from pathlib import Path

from saber.models.target import Target, TargetType
from saber.parsers.checksec import ChecksecParser
from saber.parsers.hashcat import HashcatParser
from saber.parsers.linpeas import LinpeasParser
from saber.tools.active_directory.bloodhound import BloodHoundWrapper

from tests.conftest import merge_observations

_ESC = chr(27)


# --- C5: hashcat fabricated credentials from its own status banner ----------------


def test_hashcat_status_banner_yields_no_credentials():
    """A failed crack must not poison state.credentials.

    The potfile regex matched any single-colon line, so "Status...: Exhausted"
    became a credential. That also advances the vuln_assessment phase goal, which
    fires on state.credentials being non-empty — so a FAILED crack promoted the
    mission to EXPLOITATION.
    """

    banner = (
        "hashcat (v6.2.6) starting\n"
        "Session..........: hashcat\n"
        "Status...........: Exhausted\n"
        "Recovered........: 0/1 (0.00%) Digests\n"
        "Time.Started.....: Wed Jul 30 04:00:00 2026\n"
    )
    result = HashcatParser().parse_text(banner)
    credentials = [o for o in result.observations if o.kind == "credential"]

    assert credentials == [], f"fabricated credentials from a status banner: {credentials}"


def test_hashcat_real_potfile_line_still_parses():
    """The fix must not break the case the parser exists for."""

    result = HashcatParser().parse_text("5f4dcc3b5aa765d61d8327deb882cf99:password123\n")
    credentials = [o for o in result.observations if o.kind == "credential"]

    assert len(credentials) == 1
    assert credentials[0].data["secret"] == "password123"


# --- I5: checksec "stripped" was inverted ----------------------------------------


def test_checksec_symbols_present_means_not_stripped():
    """checksec reports symbols: "yes" when symbols EXIST, i.e. NOT stripped.

    The flags dict is documented as the contract the binary-exploit loop reads, so an
    inverted value sends the exploit path down the wrong route.
    """

    entry = {"symbols": "yes", "nx": "yes", "pie": "yes", "canary": "yes", "relro": "full"}
    result = ChecksecParser().parse_json({"/bin/hardened": entry})
    flags = result.observations[0].data["metadata"]

    assert flags["stripped"] is False


def test_checksec_symbols_absent_means_stripped():
    entry = {"symbols": "no", "nx": "no", "pie": "no", "canary": "no", "relro": "no"}
    result = ChecksecParser().parse_json({"/bin/stripped": entry})

    assert result.observations[0].data["metadata"]["stripped"] is True


# --- C4: StateMerger silently discarded observation metadata ---------------------


def test_credential_metadata_survives_the_merge():
    """netexec/mimikatz/impacket attach the AD domain and realm here.

    Dropping it turns CORP\\jdoe into jdoe, which cannot be replayed against a domain.
    """

    state = merge_observations(
        [{"kind": "credential", "data": {"username": "jdoe", "metadata": {"domain": "CORP"}}}],
        tool="netexec",
        action="smb_auth_check",
    )
    assert state.credentials[0].metadata.get("domain") == "CORP"


def test_service_metadata_survives_the_merge():
    state = merge_observations(
        [{"kind": "service", "data": {"host": "h", "port": 22, "metadata": {"banner": "OpenSSH"}}}],
        tool="nmap",
        action="service_scan",
    )
    assert state.services[0].metadata.get("banner") == "OpenSSH"


def test_vuln_metadata_survives_the_merge():
    state = merge_observations(
        [{"kind": "vuln", "data": {"title": "RCE", "metadata": {"cve": "CVE-2021-4034"}}}],
        tool="nuclei",
        action="template_scan",
    )
    assert state.vulns[0].metadata.get("cve") == "CVE-2021-4034"


def test_technology_metadata_survives_the_merge():
    state = merge_observations(
        [{"kind": "technology", "data": {"host": "h", "name": "nginx", "metadata": {"x": "y"}}}],
        tool="whatweb",
        action="fingerprint",
    )
    assert state.technologies[0].metadata.get("x") == "y"


# --- I2: bloodhound ran full domain collection for ANY action string -------------


def test_bloodhound_rejects_an_unknown_action():
    """Falling through to collect() means a mislabelled action could run an
    authenticated domain-wide collection while passing every risk gate."""

    wrapper = BloodHoundWrapper(sandbox=None)
    target = Target(type=TargetType.DOMAIN, value="lab.local")

    try:
        wrapper.build_command(
            target, action="totally_bogus_action", domain="lab.local", username="jdoe"
        )
    except ValueError as exc:
        assert "action" in str(exc).lower()
    else:
        raise AssertionError("bogus action silently ran the default collection")


def test_bloodhound_known_actions_still_build():
    wrapper = BloodHoundWrapper(sandbox=None)
    target = Target(type=TargetType.DOMAIN, value="lab.local")

    collect = wrapper.build_command(
        target, action="collect", domain="lab.local", username="jdoe"
    )
    assert collect.command[0] == "bloodhound-python"

    ingest = wrapper.build_command(target, action="ingest_existing_zip", zip_path="/tmp/x.zip")
    assert ingest.command[0] == "python"


# --- I6: ANSI fixtures held literal text, so stripping was never exercised -------


def test_real_escape_sequences_are_stripped():
    """The fixtures held the literal text "[1;36m", so the ESC-only regex never fired
    and the stripping path was 100% uncovered while looking tested.

    Constructed here rather than in a fixture: raw control bytes in a committed file
    are fragile (editors and diff tools mangle them), and the parser must handle both
    forms regardless of which one reaches it.
    """

    line = f"{_ESC}[1;31m99% PE - CVE-2021-4034 (pwnkit){_ESC}[0m"
    result = LinpeasParser().parse_text(line)

    assert result.observations
    title = result.observations[0].data["title"]
    assert _ESC not in title
    assert "CVE-2021-4034" in title


def test_bare_bracket_colour_codes_are_also_stripped():
    """When something upstream eats the ESC byte, "[0m" must not survive into state."""

    line = "[1;31m99% PE - CVE-2021-4034 (pwnkit)[0m"
    result = LinpeasParser().parse_text(line)

    assert result.observations
    title = result.observations[0].data["title"]
    assert "[0m" not in title and "[1;31m" not in title
    assert "CVE-2021-4034" in title


def test_winpeas_strips_both_ansi_forms():
    from saber.parsers.winpeas import WinpeasParser

    for line in (
        f"{_ESC}[1;31m    AlwaysInstallElevated is set to 1 in both HKLM and HKCU{_ESC}[0m",
        "[1;31m    AlwaysInstallElevated is set to 1 in both HKLM and HKCU[0m",
    ):
        result = WinpeasParser().parse_text(line)
        assert result.observations, line
        title = result.observations[0].data["title"]
        assert _ESC not in title and "[0m" not in title


def test_no_ansi_residue_leaks_into_note_titles():
    """Residue like "...polkit privilege escalation[0m" was being persisted to
    MissionState and rendered into the PTES report."""

    raw = Path("tests/fixtures/sample_linpeas_output.txt").read_text()
    result = LinpeasParser().parse_text(raw)

    for observation in result.observations:
        title = str(observation.data.get("title") or "")
        detail = str(observation.data.get("detail") or "")
        assert _ESC not in title and "[0m" not in title, f"ANSI residue in title: {title!r}"
        assert _ESC not in detail and "[0m" not in detail, f"ANSI residue in detail: {detail!r}"
