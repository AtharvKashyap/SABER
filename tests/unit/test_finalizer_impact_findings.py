"""Proven impact must appear as report findings, not just as state.

A vulnerability list is not a pentest report. If the engagement got a shell, a
working credential and a flag, those are the findings a reader cares about — and
before F9 none of them reached the report at all.
"""

from saber.reporting.finalizer import ReportFinalizer


def _context(**overrides):
    context = {
        "access": {
            "sessions": [
                {"host": "10.0.0.5", "kind": "meterpreter", "user": "svc", "privilege": "system"}
            ],
            "credentials": [
                {
                    "username": "svc",
                    "secret": "***redacted***",
                    "validated": True,
                    "host": "10.0.0.5",
                    "service": "smb",
                },
                {"username": "bob", "secret": "***redacted***", "validated": False},
            ],
            "shares": [
                {"host": "10.0.0.5", "name": "ADMIN$", "type": "smb", "access": "read"},
                {"host": "10.0.0.5", "name": "PRINT$", "type": "smb", "access": "none"},
            ],
        },
        "collected": {
            "flags": [{"value": "flag{owned}", "location": "/root/flag.txt"}],
            "loot": [{"description": "id_rsa recovered", "kind": "key", "path": "/root/.ssh"}],
        },
    }
    context.update(overrides)
    return context


def _findings(**overrides):
    return ReportFinalizer._impact_findings(_context(**overrides))


def test_a_captured_flag_is_a_critical_finding():
    flag = next(f for f in _findings() if f["metadata"]["finding_kind"] == "flag")

    assert flag["severity"] == "critical"
    assert "flag{owned}" in flag["description"]
    assert "/root/flag.txt" in flag["description"]


def test_a_session_is_a_critical_finding_naming_the_host_and_privilege():
    session = next(f for f in _findings() if f["metadata"]["finding_kind"] == "session")

    assert session["severity"] == "critical"
    assert "10.0.0.5" in session["title"]
    assert "system" in session["description"]
    assert "meterpreter" in session["description"]


def test_only_validated_credentials_become_findings():
    """An unvalidated credential is a lead, not a demonstrated finding."""

    credentials = [f for f in _findings() if f["metadata"]["finding_kind"] == "credential"]

    assert len(credentials) == 1
    assert credentials[0]["metadata"]["username"] == "svc"
    assert credentials[0]["severity"] == "high"
    assert "smb" in credentials[0]["description"]


def test_loot_becomes_a_medium_finding():
    loot = next(f for f in _findings() if f["metadata"]["finding_kind"] == "loot")
    assert loot["severity"] == "medium"
    assert "id_rsa" in loot["description"]


def test_shares_with_no_access_are_not_reported_as_findings():
    shares = [f for f in _findings() if f["metadata"]["finding_kind"] == "share"]

    assert len(shares) == 1
    assert shares[0]["metadata"]["name"] == "ADMIN$"
    assert "read" in shares[0]["description"]


def test_severity_ranks_proven_access_above_collected_material():
    findings = _findings()
    by_kind = {f["metadata"]["finding_kind"]: f["severity"] for f in findings}

    assert by_kind["flag"] == "critical"
    assert by_kind["session"] == "critical"
    assert by_kind["credential"] == "high"
    assert by_kind["loot"] == "medium"


def test_redacted_secrets_stay_redacted_in_findings():
    """The adapter redacts; the finalizer must not undo it."""

    rendered = str(_findings())
    assert "***redacted***" in rendered


def test_an_empty_mission_produces_no_impact_findings():
    assert ReportFinalizer._impact_findings({}) == []
    assert ReportFinalizer._impact_findings({"access": {}, "collected": {}}) == []


def test_missing_sections_are_tolerated_for_old_snapshots():
    """Old state snapshots predate these lists; absence must not raise."""

    assert ReportFinalizer._impact_findings({"access": {"sessions": None}}) == []
