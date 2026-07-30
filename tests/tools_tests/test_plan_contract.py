from saber.models.target import Target, TargetType
from saber.tools.lateral_movement.plan import CONTRACT, LateralMovementPlannerWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_plan_paths_command_includes_source_target_and_depth():
    wrapper = LateralMovementPlannerWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="plan_paths", source="WKSTN01", max_depth=4)
    assert cmd.command == [
        "python",
        "-m",
        "saber.tools.lateral_movement.plan",
        "plan-paths",
        "--source",
        "WKSTN01",
        "--target",
        "127.0.0.1",
        "--max-depth",
        "4",
    ]
    assert cmd.action == "plan_paths"


def test_plan_paths_command_includes_graph_when_given():
    wrapper = LateralMovementPlannerWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="plan_paths", source="WKSTN01", graph_path="graph.json"
    )
    assert cmd.command == [
        "python",
        "-m",
        "saber.tools.lateral_movement.plan",
        "plan-paths",
        "--source",
        "WKSTN01",
        "--target",
        "127.0.0.1",
        "--max-depth",
        "4",
        "--graph",
        "graph.json",
    ]


def test_rank_paths_command_defaults_criteria_to_lowest_risk():
    wrapper = LateralMovementPlannerWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="rank_paths",
        candidate_paths_file="lateral_movement/plan/paths/candidates.json",
    )
    assert cmd.command == [
        "python",
        "-m",
        "saber.tools.lateral_movement.plan",
        "rank-paths",
        "--input",
        "lateral_movement/plan/paths/candidates.json",
        "--criteria",
        "lowest_risk",
    ]


def test_export_plan_command_defaults_output_format_to_json():
    wrapper = LateralMovementPlannerWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="export_plan", plan_id="plan-001")
    assert cmd.command == [
        "python",
        "-m",
        "saber.tools.lateral_movement.plan",
        "export-plan",
        "--plan-id",
        "plan-001",
        "--format",
        "json",
    ]


def test_every_action_is_low_risk_and_autonomous():
    for action in CONTRACT.actions:
        assert action.risk == "low", action.action
        assert action.requires_approval is False, action.action


def test_no_action_declares_a_reserved_arg_name():
    reserved = {"target", "session", "action", "metadata"}
    for action in CONTRACT.actions:
        names = {spec.name for spec in action.args}
        assert not (names & reserved), (action.action, names)
        assert not (set(action.example_args) & reserved), action.action
