from saber.core.canonical_kinds import CANONICAL_KINDS
from saber.core.state_merger import StateMerger


def test_mergers_cover_exactly_the_canonical_vocabulary():
    assert set(StateMerger._MERGERS.keys()) == set(CANONICAL_KINDS)


def test_vocabulary_is_the_expected_eleven():
    assert CANONICAL_KINDS == frozenset({
        "host", "service", "technology", "credential", "vuln",
        "share", "account", "session", "loot", "flag", "note",
    })
