from saber.tools.registry import build_default_registry


def test_custom_cli_is_registered():
    reg = build_default_registry()
    assert reg.has("custom_cli")
    entry = reg.get("custom_cli")
    assert entry.class_name == "CustomCliWrapper"
