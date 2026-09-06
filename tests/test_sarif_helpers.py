"""Tests for the reused SARIF helpers.

The behaviour asserted here is inherited from stride-gpt's own test suite
(tests/test_report_sarif.py in that project) — retained so the reused code keeps
working after being generalised. Attribution: stride-gpt, MIT, (c) 2024 Matt
Adams. See THIRD_PARTY_NOTICES.md.
"""
from pyrastride.sarif_helpers import make_sarif_rule_id, sarif_text


def test_clean_type():
    assert make_sarif_rule_id("STRIDE", "Spoofing") == "STRIDE/SPOOFING"


def test_hostile_chars_are_stripped():
    rid = make_sarif_rule_id("STRIDE", "../etc/passwd <script>")
    body = rid.split("/", 1)[1]
    assert all(c.isupper() or c.isdigit() or c == "_" for c in body)


def test_empty_becomes_unknown():
    assert make_sarif_rule_id("STRIDE", "") == "STRIDE/UNKNOWN"


def test_none_becomes_unknown():
    assert make_sarif_rule_id("STRIDE", None) == "STRIDE/UNKNOWN"


def test_prefix_is_parameterised():
    # PyraStride's generalisation: the namespace is an argument, not hard-coded.
    assert make_sarif_rule_id("PYRA", "Tampering") == "PYRA/TAMPERING"


def test_sarif_text_bounds_length():
    long = "x" * 6000
    out = sarif_text(long)
    assert out.endswith("…[truncated]")
    assert len(out) < 6000


def test_sarif_text_handles_none():
    assert sarif_text(None) == ""
