from saber.models.target import Target, TargetType
from saber.tools.reverse_engineering.ghidra_headless import CONTRACT, GhidraHeadlessWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_analyze_binary_command_without_postscript():
    wrapper = GhidraHeadlessWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="analyze_binary",
        binary_path="/tmp/challenge.bin",
        project_dir="/tmp/ghidra_proj",
        project_name="saber_analysis",
    )
    assert cmd.command == [
        "analyzeHeadless",
        "/tmp/ghidra_proj",
        "saber_analysis",
        "-import",
        "/tmp/challenge.bin",
        "-overwrite",
        "-analysisTimeoutPerFile",
        "1800",
    ]
    assert cmd.action == "analyze_binary"


def test_analyze_binary_command_with_postscript_and_args():
    wrapper = GhidraHeadlessWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="analyze_binary",
        binary_path="/tmp/challenge.bin",
        project_dir="/tmp/ghidra_proj",
        project_name="saber_analysis",
        script_path="/opt/ghidra_scripts/DecompileSummary.java",
        script_args=["--verbose"],
    )
    assert cmd.command == [
        "analyzeHeadless",
        "/tmp/ghidra_proj",
        "saber_analysis",
        "-import",
        "/tmp/challenge.bin",
        "-overwrite",
        "-analysisTimeoutPerFile",
        "1800",
        "-postScript",
        "/opt/ghidra_scripts/DecompileSummary.java",
        "--verbose",
    ]


def test_run_script_command():
    wrapper = GhidraHeadlessWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="run_script",
        project_dir="/tmp/ghidra_proj",
        project_name="saber_analysis",
        script_path="/opt/ghidra_scripts/DecompileSummary.java",
    )
    assert cmd.command == [
        "analyzeHeadless",
        "/tmp/ghidra_proj",
        "saber_analysis",
        "-process",
        "-postScript",
        "/opt/ghidra_scripts/DecompileSummary.java",
    ]
    assert cmd.action == "run_script"


def test_export_analysis_command():
    wrapper = GhidraHeadlessWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="export_analysis",
        binary_path="/tmp/challenge.bin",
        project_dir="/tmp/ghidra_proj",
        project_name="saber_analysis",
        export_script="/opt/ghidra_scripts/ExportDecompiled.java",
        output_file="/tmp/decompiled_summary.txt",
    )
    assert cmd.command == [
        "analyzeHeadless",
        "/tmp/ghidra_proj",
        "saber_analysis",
        "-import",
        "/tmp/challenge.bin",
        "-overwrite",
        "-postScript",
        "/opt/ghidra_scripts/ExportDecompiled.java",
        "/tmp/decompiled_summary.txt",
    ]
    assert cmd.action == "export_analysis"


def test_contract_matches_wrapper_category_and_phase():
    wrapper = GhidraHeadlessWrapper(sandbox=None)
    assert CONTRACT.category == wrapper.config.category.value
    assert CONTRACT.phase == wrapper.config.phase.value


def test_only_run_script_is_approval_gated():
    gated = {a.action for a in CONTRACT.actions if a.requires_approval}
    assert gated == {"run_script"}
    for action in CONTRACT.actions:
        if action.action == "run_script":
            assert action.risk == "medium"
        else:
            assert action.risk == "low"
            assert action.requires_approval is False
