from saber.core.scope_loader import load_scope


def test_load_scope_reads_targets(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text("mission_name: Lab\ntargets:\n  - dvwa\n  - metasploitable\n")
    scope = load_scope(p)
    assert scope.mission_name == "Lab"
    assert set(scope.target_values()) == {"dvwa", "metasploitable"}
