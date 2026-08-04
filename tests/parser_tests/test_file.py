from pathlib import Path

from saber.parsers.file import FileParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_file_output.txt")


def _observations():
    result = FileParser().parse_text(_FIXTURE.read_text())
    return result, [o.to_dict() for o in result.observations]


def test_one_note_per_identified_file():
    _, obs = _observations()
    assert len(obs) == 6
    assert {o["kind"] for o in obs} == {"note"}


def test_path_and_description_are_split():
    _, obs = _observations()
    vulnbin = next(o for o in obs if "vulnbin" in o["data"]["title"])

    assert_observation(
        vulnbin,
        kind="note",
        data_subset={"title": "File type: /opt/lab/vulnbin"},
    )
    assert vulnbin["data"]["detail"].startswith("ELF 64-bit LSB executable")
    assert vulnbin["data"]["metadata"]["path"] == "/opt/lab/vulnbin"


def test_executables_and_archives_are_flagged():
    _, obs = _observations()
    by_path = {o["data"]["metadata"]["path"]: o["data"]["metadata"] for o in obs}

    assert by_path["/opt/lab/vulnbin"]["executable"] is True
    assert by_path["/opt/lab/agent.exe"]["executable"] is True
    assert by_path["/opt/lab/backup.tar.gz"]["archive"] is True
    assert by_path["/opt/lab/notes.txt"]["executable"] is False


def test_setuid_binary_outranks_a_plain_executable():
    _, obs = _observations()
    by_path = {o["data"]["metadata"]["path"]: o["data"] for o in obs}

    assert by_path["/opt/lab/setuid-helper"]["severity"] == "high"
    assert by_path["/opt/lab/vulnbin"]["severity"] == "medium"
    assert by_path["/opt/lab/backup.tar.gz"]["severity"] == "low"
    assert by_path["/opt/lab/notes.txt"]["severity"] == "info"


def test_brief_output_recovers_the_path_from_metadata():
    result = FileParser().parse_text(
        "ELF 64-bit LSB executable, x86-64\n", metadata={"file_path": "/opt/lab/vulnbin"}
    )
    obs = result.observations[0].to_dict()
    assert obs["data"]["title"] == "File type: /opt/lab/vulnbin"
    assert obs["data"]["metadata"]["executable"] is True


def test_file_grows_state_notes():
    _, obs = _observations()
    state = merge_observations(obs, tool="file", action="directory")
    assert len(state.notes) == 6


def test_file_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "\n\n"):
        result = FileParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
