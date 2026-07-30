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


# --- C3: nmap ran in stdout mode, where product/version do not exist -------------


def test_nmap_service_scan_requests_xml_on_stdout():
    """Without -oX, nmap's human-readable output carries no product/version, so
    everything -sV was run to obtain was silently discarded at merge time."""

    from saber.tools.recon.nmap import NmapWrapper

    wrapper = NmapWrapper(sandbox=None)
    for action in ("service_scan", "vuln_scan", "udp_scan"):
        cmd = wrapper.build_command(Target(type=TargetType.IP, value="10.0.0.5"), action=action)
        assert "-oX" in cmd.command, f"{action} does not request XML"
        assert cmd.command[cmd.command.index("-oX") + 1] == "-"


def test_nmap_xml_product_and_version_reach_state():
    """The forcing assertion: merge the XML and check state, not the observation."""

    from saber.parsers.nmap import NmapParser

    xml = Path("tests/fixtures/sample_nmap_output.xml").read_text()
    result = NmapParser().parse_text(xml)
    observations = [o.to_dict() for o in result.observations]
    state = merge_observations(observations, tool="nmap", action="service_scan")

    with_product = [s for s in state.services if s.product]
    assert with_product, "no service reached state with a product; -sV data was lost"
    assert with_product[0].version, "product survived but version did not"


def test_nmap_cpes_survive_into_service_metadata():
    """KnownService has no cpes field, so they were dropped entirely."""

    from saber.parsers.nmap import NmapParser

    xml = Path("tests/fixtures/sample_nmap_output.xml").read_text()
    result = NmapParser().parse_text(xml)
    observations = [o.to_dict() for o in result.observations]
    state = merge_observations(observations, tool="nmap", action="service_scan")

    cpes = [s.metadata.get("cpes") for s in state.services if s.metadata.get("cpes")]
    assert cpes, "cpes were discarded at merge; CVE correlation has no input"


# --- M3: parsers keyed on formats real tools do not emit --------------------------


def test_john_live_crack_output_is_parsed():
    """A successful dictionary_attack prints "secret  (user)", NOT --show format.

    The spec routes dictionary_attack/single_crack to this parser, so keying only on
    --show meant a SUCCESSFUL crack produced zero observations.
    """

    from saber.parsers.john import JohnParser

    text = (
        "Using default input encoding: UTF-8\n"
        "Loaded 2 password hashes with 2 different salts (sha512crypt)\n"
        "Press 'q' or Ctrl-C to abort, almost any other key for status\n"
        "Summer2023!      (jdoe)\n"
        "toor             (root)\n"
        "2g 0:00:00:03 DONE (2026-07-30 04:00) 0.6g/s\n"
        "Session completed.\n"
    )
    result = JohnParser().parse_text(text)
    credentials = {o.data["username"]: o.data["secret"] for o in result.observations}

    assert credentials == {"jdoe": "Summer2023!", "root": "toor"}
    assert all(o.data["validated"] is False for o in result.observations)


def test_john_progress_noise_is_not_a_credential():
    from saber.parsers.john import JohnParser

    text = "Loaded 1 password hash (bcrypt)\nSession completed.\n"
    result = JohnParser().parse_text(text)
    assert result.observations == []


def test_nikto_modern_finding_without_osvdb_is_reported():
    """Nikto 2.5 dropped OSVDB (retired 2016). Requiring it made real scans look clean."""

    from saber.parsers.nikto import NiktoParser

    text = (
        "+ Target IP:          10.0.0.5\n"
        "+ /: The X-Content-Type-Options header is not set.\n"
        "+ /login: Cookie without HttpOnly flag detected. See: CVE-2022-1234\n"
        "+ 7915 requests: 0 error(s) and 2 item(s) reported on remote host\n"
    )
    result = NiktoParser().parse_text(text, metadata={"target": "10.0.0.5"})
    titles = [o.data["title"] for o in result.observations]

    assert len(result.observations) == 2, titles
    identifiers = {o.data["identifier"] for o in result.observations}
    assert "CVE-2022-1234" in identifiers
    assert None in identifiers


def test_nikto_scan_summary_is_not_a_finding():
    from saber.parsers.nikto import NiktoParser

    text = "+ Target IP: 10.0.0.5\n+ 7915 requests: 0 error(s) and 0 item(s) reported\n"
    result = NiktoParser().parse_text(text)
    assert result.observations == []


def test_nikto_severity_matches_whole_words_only():
    """Substring matching made "low" fire on "Allowed" and "info" on "information"."""

    from saber.parsers.nikto import NiktoParser

    result = NiktoParser().parse_text(
        "+ Target IP: 10.0.0.5\n+ OSVDB-1: OPTIONS: Allowed HTTP methods are POST.\n"
    )
    assert result.observations[0].data["severity"] == "info", "'Allowed' matched 'low'"


def test_linpeas_real_ls_style_suid_row_is_parsed():
    """Real linpeas SUID rows are ls-style and never contain the word "suid".

    The old pattern required BOTH the substring "suid" AND an arrow, so neither real
    form matched and the headline SUID signal never fired in production.
    """

    text = (
        "-rwsr-xr-x 1 root root 31K Feb 21  2022 /usr/bin/pkexec  --->  CVE-2021-4034\n"
        "-rwsr-xr-x 1 root root 55K Jan  1  2024 /usr/bin/passwd\n"
    )
    result = LinpeasParser().parse_text(text)
    notes = {o.data["title"]: o.data for o in result.observations if o.kind == "note"}

    assert "Notable SUID binary: /usr/bin/pkexec" in notes
    assert "Notable SUID binary: /usr/bin/passwd" in notes
    # An attached CVE means linpeas knows an exploit — that outranks a plain SUID.
    assert notes["Notable SUID binary: /usr/bin/pkexec"]["severity"] == "high"
    assert notes["Notable SUID binary: /usr/bin/passwd"]["severity"] == "medium"


def test_winpeas_real_privilege_state_is_parsed():
    """Real winPEAS prints "SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED".

    Requiring "ENABLED" immediately after the colon meant the real form never matched,
    so the primary Windows privesc signal never fired.
    """

    from saber.parsers.winpeas import WinpeasParser

    text = "    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED\n"
    result = WinpeasParser().parse_text(text)
    note = result.observations[0].to_dict()

    assert note["data"]["title"] == "Token privilege enabled: SeImpersonatePrivilege"
    assert note["data"]["severity"] == "critical"


def test_winpeas_disabled_privilege_is_not_reported_as_enabled():
    from saber.parsers.winpeas import WinpeasParser

    result = WinpeasParser().parse_text("    SeShutdownPrivilege: SE_PRIVILEGE_DISABLED\n")
    titles = [o.data.get("title", "") for o in result.observations]
    assert not any("Token privilege enabled" in t for t in titles)


def test_impacket_system_whoami_is_parsed():
    """A psexec foothold lands as SYSTEM: whoami prints "nt authority\\system".

    The domain charset had no space, so the normal and most important case never
    matched — a successful psexec produced no session and privilege="system" was dead.
    """

    from saber.parsers.impacket import ImpacketParser

    text = "[*] Starting service abcd\nnt authority\\system\n"
    result = ImpacketParser().parse_text(text, metadata={"target": "10.0.0.5"})
    sessions = [o for o in result.observations if o.kind == "session"]

    assert sessions, "no session recorded for a SYSTEM psexec foothold"
    assert sessions[0].data["privilege"] == "system"


def test_netexec_user_header_row_is_not_an_account():
    """nxc --users prints a "-Username-  -Last PW Set-" header row."""

    from saber.parsers.netexec import NetExecParser

    text = (
        "LDAP        10.0.0.5  389  DC01  -Username-  -Last PW Set-  -BadPW-  -Description-\n"
        "LDAP        10.0.0.5  389  DC01  jdoe        2026-01-01     0        John Doe\n"
    )
    result = NetExecParser().parse_text(text)
    usernames = {o.data["username"] for o in result.observations if o.kind == "account"}

    assert usernames == {"jdoe"}, f"header row parsed as an account: {usernames}"
