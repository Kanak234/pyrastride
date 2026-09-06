"""Tests for the original SARIF-ingestion, prioritisation, and emission logic."""
import json

import pytest

from pyrastride.bridge import (
    prioritise,
    remediation_plan,
    to_sarif,
)


def _pyrasec_sarif(*results):
    """A minimal PyraSec-shaped SARIF document."""
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "PyraSec"}}, "results": list(results)}],
    }


def _finding(rule_id, text, level="error", uri="app.py", line=10, confidence=1.0):
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": text},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}
        ],
        "properties": {"confidence": confidence},
    }


def test_prioritise_ranks_elevation_above_repudiation():
    doc = _pyrasec_sarif(
        _finding("SEC090", "Audit logging disabled", level="warning"),
        _finding("SEC001", "Privileged container found", level="error"),
    )
    ranked = prioritise(doc)
    assert ranked[0].rule_id == "SEC001"          # elevation, error
    assert ranked[0].threat_score > ranked[1].threat_score


def test_confidence_scales_the_score():
    hi = prioritise(_pyrasec_sarif(_finding("SEC001", "secret key", confidence=1.0)))[0]
    lo = prioritise(_pyrasec_sarif(_finding("SEC001", "secret key", confidence=0.3)))[0]
    assert hi.threat_score > lo.threat_score


def test_location_is_parsed():
    f = prioritise(_pyrasec_sarif(_finding("SEC001", "secret", uri="conf/app.py", line=42)))[0]
    assert f.location == "conf/app.py:42"


def test_emitted_sarif_is_valid_shape():
    doc = _pyrasec_sarif(_finding("SEC001", "AWS secret key"))
    out = to_sarif(prioritise(doc))
    assert out["version"] == "2.1.0"
    run = out["runs"][0]
    assert run["tool"]["driver"]["name"] == "PyraStride"
    # ruleId is a sanitised STRIDE id, never the raw PyraSec id
    rid = run["results"][0]["ruleId"]
    assert rid.startswith("STRIDE/")
    # round-trips as JSON (real SARIF consumers parse it)
    json.loads(json.dumps(out))


def test_emitted_sarif_carries_stride_properties():
    out = to_sarif(prioritise(_pyrasec_sarif(_finding("SEC001", "secret key"))))
    props = out["runs"][0]["results"][0]["properties"]
    assert "pyrastride/strideCategories" in props
    assert "pyrastride/threatScore" in props
    assert "security-severity" in props   # GitHub code-scanning reads this


def test_bad_root_raises():
    with pytest.raises((TypeError, ValueError)):
        prioritise(["not", "a", "sarif", "object"])


def test_empty_runs_yields_no_findings():
    assert prioritise({"runs": []}) == []


def test_remediation_plan_is_markdown_and_ordered():
    doc = _pyrasec_sarif(
        _finding("SEC090", "logging disabled", level="note"),
        _finding("SEC001", "privileged container", level="error"),
    )
    plan = remediation_plan(prioritise(doc))
    assert plan.startswith("# PyraStride")
    # highest-threat finding appears before the lower one in the text
    assert plan.index("SEC001") < plan.index("SEC090")
