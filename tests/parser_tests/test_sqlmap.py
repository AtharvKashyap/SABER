"""Tests for SqlmapParser."""

from __future__ import annotations

from pathlib import Path

from saber.parsers.sqlmap import SqlmapParser

from tests.conftest import assert_observation, merge_observations


class TestSqlmapParser:
    """Validate sqlmap parser."""

    def test_empty_output_fails(self) -> None:
        """Empty output should fail."""

        result = SqlmapParser().parse_text("")

        assert result.success is False
        assert result.errors == ["sqlmap output is empty."]

    def test_no_injection_yields_note(self) -> None:
        """No confirmed injection point should yield a note, not a vuln."""

        text = "[10:00:00] [INFO] all tested parameters do not appear to be injectable"

        result = SqlmapParser().parse_text(text)

        assert result.success is True
        assert len(result.observations) == 1
        observation = result.observations[0]
        assert observation.kind == "note"
        assert observation.data["title"] == "sqlmap scan: no confirmed injection"

    def test_confirmed_injection_yields_vuln(self) -> None:
        """A confirmed injection point should yield a high-severity confirmed vuln."""

        text = (
            "sqlmap identified the following injection point(s) "
            "with a total of 1 HTTP(s) requests:\n"
            "---\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
            "    Payload: id=1 AND 1=1\n"
            "---\n"
            "back-end DBMS: MySQL >= 5.0\n"
        )

        result = SqlmapParser().parse_text(text, metadata={"url": "https://example.com/item?id=1"})

        assert result.success is True
        assert len(result.observations) == 1
        observation = result.observations[0]
        assert observation.kind == "vuln"
        assert observation.data["host"] == "example.com"
        assert observation.data["severity"] == "high"
        assert observation.data["confirmed"] is True
        assert observation.data["identifier"] == "MySQL >= 5.0"
        assert "AND boolean-based blind" in observation.data["title"]


def test_sqlmap_fixture_emits_vulns_and_grows_state() -> None:
    """Fixture sqlmap output with a confirmed injection yields canonical vulns that grow state."""

    text = Path("tests/fixtures/sample_sqlmap_output.txt").read_text()
    result = SqlmapParser().parse_text(text, metadata={"url": "https://example.com/item?id=1"})
    obs = [o.to_dict() for o in result.observations]
    vulns = [o for o in obs if o["kind"] == "vuln"]
    assert len(vulns) == 2
    assert_observation(
        vulns[0],
        kind="vuln",
        data_subset={
            "host": "example.com",
            "severity": "high",
            "confirmed": True,
        },
    )
    state = merge_observations(obs, tool="sqlmap", action="injection_test")
    assert len(state.vulns) == 2
