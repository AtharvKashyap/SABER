"""Tests for SearchSploitParser."""

from __future__ import annotations

from saber.parsers.searchsploit import SearchSploitParser


class TestSearchSploitParser:
    """Validate SearchSploit parser."""

    def test_empty_output_fails(self) -> None:
        """Empty output should fail."""

        result = SearchSploitParser().parse_text("")

        assert result.success is False
        assert result.errors == ["SearchSploit output is empty."]

    def test_parse_json_results_exploit(self) -> None:
        """SearchSploit JSON should produce exploit references."""

        data = {
            "RESULTS_EXPLOIT": [
                {
                    "Title": "Apache Struts RCE",
                    "EDB-ID": "12345",
                    "Path": "exploits/linux/remote/12345.py",
                    "Platform": "linux",
                    "Type": "remote",
                    "Date": "2024-01-01",
                }
            ]
        }

        result = SearchSploitParser().parse_json(data)

        assert result.success is True
        assert len(result.observations) == 1

        observation = result.observations[0]
        assert observation.kind == "exploit_reference"
        assert observation.data["title"] == "Apache Struts RCE"
        assert observation.data["edb_id"] == "12345"
        assert observation.data["path"] == "exploits/linux/remote/12345.py"
        assert observation.data["platform"] == "linux"
        assert observation.data["type"] == "remote"
        assert "EDB-ID 12345" in observation.summary

    def test_parse_json_text(self) -> None:
        """JSON text should route to parse_json."""

        text = '{"RESULTS_EXPLOIT":[{"Title":"Example Exploit","EDB-ID":"999","Path":"exploits/999.py"}]}'

        result = SearchSploitParser().parse_text(text)

        assert result.success is True
        assert result.observations[0].data["edb_id"] == "999"

    def test_parse_json_list(self) -> None:
        """List JSON should parse."""

        result = SearchSploitParser().parse_json(
            [{"title": "Example", "edb_id": "1", "path": "exploits/1.py"}]
        )

        assert result.success is True
        assert result.observations[0].data["title"] == "Example"

    def test_parse_stdout_table(self) -> None:
        """Stdout table should parse exploit references."""

        text = """
Exploit Title                                      | Path
-------------------------------------------------- ---------------------------------
Apache Struts RCE                                 | exploits/linux/remote/12345.py
WordPress Plugin X SQLi                           | exploits/php/webapps/55555.txt
"""

        result = SearchSploitParser().parse_text(text)

        assert result.success is True
        assert result.metadata["format"] == "stdout"
        assert len(result.observations) == 2
        assert result.observations[0].data["title"] == "Apache Struts RCE"
        assert result.observations[0].data["edb_id"] == "12345"
        assert result.observations[1].data["edb_id"] == "55555"

    def test_parse_unrecognized_stdout_fails(self) -> None:
        """Unrecognized stdout should fail."""

        result = SearchSploitParser().parse_text("No Results")

        assert result.success is False
        assert result.errors == ["No SearchSploit stdout references could be parsed."]

    def test_parse_json_without_records_fails(self) -> None:
        """JSON without useful records should fail."""

        result = SearchSploitParser().parse_json({"RESULTS_EXPLOIT": []})

        assert result.success is False
        assert result.errors == ["No SearchSploit exploit references could be parsed."]
