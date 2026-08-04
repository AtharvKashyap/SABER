from saber.core.flag_detector import detect_flag


def test_detects_picoctf():
    assert detect_flag(["got picoCTF{s0me_fl4g} here"]) == "picoCTF{s0me_fl4g}"


def test_detects_lowercase_flag():
    assert detect_flag(["flag{abc_123}"]) == "flag{abc_123}"


def test_detects_uppercase_flag():
    assert detect_flag(["FLAG{ABC}"]) == "FLAG{ABC}"


def test_detects_ctf():
    assert detect_flag(["CTF{x}"]) == "CTF{x}"


def test_returns_first_match_across_texts():
    assert detect_flag(["nothing", "flag{first}", "flag{second}"]) == "flag{first}"


def test_no_match_returns_none():
    assert detect_flag(["no flags here", "flagpole", "{}"]) is None


def test_extra_pattern_matches_custom_format():
    assert detect_flag(["KEY-abc-999"], extra_patterns=[r"KEY-[a-z]+-\d+"]) == "KEY-abc-999"


def test_ignores_empty_and_non_string():
    assert detect_flag(["", None, "flag{ok}"]) == "flag{ok}"  # type: ignore[list-item]
