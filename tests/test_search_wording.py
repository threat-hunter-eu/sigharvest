"""Natural wording finds the same rules: light stemming on prefix words, phrases untouched."""

import pytest

from sigharvest.index import fts_query, stem


@pytest.mark.parametrize(
    "word,expected",
    [("dumping", "dump"), ("dumped", "dump"), ("dumps", "dump"), ("credentials", "credential"), ("processes", "process"), ("queries", "quer")],
)
def test_stem(word, expected):
    assert stem(word) == expected


@pytest.mark.parametrize("word", ["lsass", "analysis", "access", "mimikatz", "T1003", "dump", "exe"])
def test_stem_leaves_short_digit_and_non_plural_words(word):
    assert stem(word) == word


def test_natural_phrase_matches_short_form():
    assert fts_query("LSASS dumping")[0] == fts_query("LSASS dump")[0]
    assert fts_query('"lsass dumping"')[0] == '"lsass dumping"*'  # quoted phrases are exact
    assert fts_query("title:dumping")[0] == 'title:"dump"*'
