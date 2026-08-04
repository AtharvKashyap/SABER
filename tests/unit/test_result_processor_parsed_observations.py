from saber.core.result_processor import ProcessedToolResult


def test_processed_result_defaults_parsed_observations_empty():
    result = ProcessedToolResult(session_id="s", step_id=None, tool_name="nmap")
    assert result.parsed_observations == []
