"""F9: the report must reflect everything the arsenal produces, phased.

Before F9 the adapter emitted hosts/services/technologies/credentials/vulns only, so
a mission that established sessions, dumped loot and captured a flag reported none of
it. These tests pin the PTES structure and the redaction rules.
"""

from saber.models.mission_state import (
    AttemptedAction,
    KnownAccount,
    KnownCredential,
    KnownFlag,
    KnownHost,
    KnownLoot,
    KnownService,
    KnownSession,
    KnownShare,
    KnownVuln,
    MissionNote,
    MissionState,
    PtesPhase,
)
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.reporting.state_report_adapter import MissionStateReportAdapter


def _target():
    return Target(type=TargetType.IP, value="10.0.0.5")


def _session():
    return MissionSession(mission_name="m", target=_target())


def _rich_state(**updates) -> MissionState:
    state = MissionState(
        session_id="s",
        target=_target(),
        objective="prove impact",
        current_phase=PtesPhase.LATERAL_MOVEMENT,
        hosts=[KnownHost(address="10.0.0.5"), KnownHost(address="10.0.0.9")],
        services=[KnownService(host="10.0.0.5", port=445, service="smb")],
        vulns=[KnownVuln(title="MS17-010", confirmed=True)],
        credentials=[
            KnownCredential(username="svc", secret="FakeLabPass", validated=True, host="10.0.0.5"),
            KnownCredential(username="bob", secret="cracked", validated=False),
        ],
        sessions=[
            KnownSession(host="10.0.0.5", kind="shell"),
            KnownSession(host="10.0.0.9", kind="winrm"),
        ],
        accounts=[KnownAccount(username="admin", domain="LAB")],
        shares=[KnownShare(host="10.0.0.5", name="ADMIN$", access="read")],
        loot=[
            KnownLoot(
                description="Embedded connection string: postgres://labuser:S3cret@db/appdb",
                kind="config",
                path="/opt/app/config.ini",
            ),
            KnownLoot(description="Embedded secret assignment: api_key=ABCDEF", kind="config"),
        ],
        flags=[KnownFlag(value="flag{owned}")],
        notes=[
            MissionNote(
                title="Phase complete: recon -> vuln_assessment",
                detail="2 host(s), 1 service(s), 0 technology/ies discovered",
                metadata={"from_phase": "recon", "to_phase": "vuln_assessment", "step": 3},
            ),
            MissionNote(
                title="Phase complete: exploitation -> post_exploitation",
                detail="2 session(s) established",
                metadata={
                    "from_phase": "exploitation",
                    "to_phase": "post_exploitation",
                    "step": 7,
                },
            ),
        ],
        attempted_actions=[
            AttemptedAction(tool_name="nmap", action="service_scan", success=True),
        ],
    )
    return state.model_copy(update=updates) if updates else state


def _context(state=None):
    return MissionStateReportAdapter().build_report_context(state or _rich_state(), _session())


# --- coverage of the extended state ----------------------------------------------


def test_report_includes_access_obtained():
    access = _context()["access"]

    assert len(access["sessions"]) == 2
    assert len(access["accounts"]) == 1
    assert len(access["shares"]) == 1
    assert len(access["credentials"]) == 2


def test_report_includes_what_was_collected():
    collected = _context()["collected"]

    assert len(collected["loot"]) == 2
    assert [flag["value"] for flag in collected["flags"]] == ["flag{owned}"]


def test_report_includes_notes_and_current_phase():
    context = _context()
    assert context["current_phase"] == "lateral_movement"
    assert context["notes"]


# --- methodology ------------------------------------------------------------------


def test_methodology_lists_every_phase_in_order():
    methodology = _context()["methodology"]
    assert [entry["phase"] for entry in methodology] == [p.value for p in PtesPhase.ordered()]


def test_methodology_marks_reached_phases_up_to_the_current_one():
    methodology = {entry["phase"]: entry for entry in _context()["methodology"]}

    assert methodology["recon"]["reached"] is True
    assert methodology["lateral_movement"]["reached"] is True
    # Not yet reached.
    assert methodology["proof_of_concept"]["reached"] is False
    assert methodology["post_engagement"]["reached"] is False


def test_methodology_carries_the_evidence_that_completed_a_phase():
    """Recovered from the transition notes the loop wrote — not re-derived."""

    methodology = {entry["phase"]: entry for entry in _context()["methodology"]}

    recon = methodology["recon"]
    assert recon["completed"] is True
    assert "2 host(s)" in recon["evidence"]
    assert recon["completed_at_step"] == 3

    # A phase the loop never recorded completing.
    assert methodology["lateral_movement"]["completed"] is False
    assert methodology["lateral_movement"]["evidence"] is None


# --- attack chain -----------------------------------------------------------------


def test_attack_chain_narrates_how_access_was_obtained():
    steps = [entry["step"] for entry in _context()["attack_chain"]]

    assert "reconnaissance" in steps
    assert "vulnerability_identified" in steps
    assert "credentials_validated" in steps
    assert "foothold_established" in steps
    assert "lateral_movement" in steps
    assert "data_collected" in steps
    assert "objective_proven" in steps


def test_attack_chain_order_follows_the_engagement():
    steps = [entry["step"] for entry in _context()["attack_chain"]]
    assert steps.index("reconnaissance") < steps.index("foothold_established")
    assert steps.index("foothold_established") < steps.index("objective_proven")


def test_lateral_movement_only_claimed_with_more_than_one_host():
    single = _rich_state(sessions=[KnownSession(host="10.0.0.5", kind="shell")])
    steps = [entry["step"] for entry in _context(single)["attack_chain"]]

    assert "foothold_established" in steps
    assert "lateral_movement" not in steps


def test_attack_chain_appends_the_deterministic_phase_evidence():
    steps = [entry["step"] for entry in _context()["attack_chain"]]
    assert "phase_complete:recon" in steps
    assert "phase_complete:exploitation" in steps


def test_an_empty_mission_produces_an_empty_chain_not_a_fake_one():
    bare = MissionState(session_id="s", target=_target())
    assert _context(bare)["attack_chain"] == []


# --- redaction --------------------------------------------------------------------


def test_credential_secrets_are_redacted_but_their_existence_is_recorded():
    credentials = {c["username"]: c for c in _context()["access"]["credentials"]}

    assert credentials["svc"]["secret"] == "***redacted***"
    assert credentials["svc"]["validated"] is True
    assert "FakeLabPass" not in str(_context())


def test_inline_password_in_loot_is_masked_but_the_finding_survives():
    loot = _context()["collected"]["loot"]
    connection = next(item for item in loot if "postgres://" in item["description"])

    assert "S3cret" not in connection["description"]
    assert "postgres://labuser:***redacted***@" in connection["description"]
    # The finding is still legible and still points at the file.
    assert connection["path"] == "/opt/app/config.ini"


def test_assigned_secret_in_loot_is_masked():
    loot = _context()["collected"]["loot"]
    assignment = next(item for item in loot if "api_key" in item["description"])

    assert "ABCDEF" not in assignment["description"]
    assert "***redacted***" in assignment["description"]


def test_no_secret_material_leaks_anywhere_into_the_context():
    """A report gets emailed around; secrets must not ride along."""

    rendered = str(_context())
    for secret in ("FakeLabPass", "S3cret", "ABCDEF"):
        assert secret not in rendered


def test_flags_are_not_redacted_because_they_are_the_deliverable():
    assert _context()["collected"]["flags"][0]["value"] == "flag{owned}"


def test_redact_secrets_is_reusable_and_leaves_clean_text_alone():
    adapter = MissionStateReportAdapter()
    assert adapter.redact_secrets("nothing sensitive here") == "nothing sensitive here"
    assert "***redacted***" in adapter.redact_secrets("password: hunter2")


# --- back-compat ------------------------------------------------------------------


def test_old_keys_are_still_present_for_existing_exporters():
    context = _context()
    for key in ("summary", "session", "hosts", "services", "technologies", "vulns"):
        assert key in context
    assert "timeline" in context
    assert "evidence_refs" in context
    assert "stop_reason" in context
