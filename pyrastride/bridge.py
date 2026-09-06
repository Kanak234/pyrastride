"""Ingest a PyraSec SARIF file and emit a STRIDE-annotated, threat-prioritised
SARIF plus a remediation plan.

Original work. This is the heart of PyraStride: it reads the SARIF that PyraSec
already produces, attaches a threat-model view to every finding, and re-ranks
them by threat weight rather than raw severity.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .sarif_helpers import make_sarif_rule_id, sarif_text
from .stride_map import StrideMatch, category_weight, map_finding

# SARIF level -> a base severity weight. PyraSec emits SARIF levels
# error/warning/note; we translate them to a 0..1 base.
_LEVEL_WEIGHT = {"error": 1.0, "warning": 0.6, "note": 0.3, "none": 0.1}


@dataclass
class PrioritisedFinding:
    rule_id: str
    message: str
    level: str
    location: str
    stride: StrideMatch
    base_weight: float
    threat_score: float
    properties: dict[str, Any] = field(default_factory=dict)


def _iter_sarif_results(doc: dict[str, Any]):
    """Yield (result, run) for every result in a SARIF document.

    Tolerant of the parts PyraSec may or may not populate — a real ingestion
    boundary, so it validates shape instead of trusting it.
    """
    if not isinstance(doc, dict):
        raise ValueError("SARIF root is not an object")
    for run in doc.get("runs", []) or []:
        for res in run.get("results", []) or []:
            yield res, run


def _location_of(result: dict[str, Any]) -> str:
    try:
        loc = result["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"]
        line = loc.get("region", {}).get("startLine")
        return f"{uri}:{line}" if line else uri
    except (KeyError, IndexError, TypeError):
        return "(unknown location)"


def _confidence_of(result: dict[str, Any]) -> float:
    """PyraSec attaches a confidence in result.properties; default to 1.0."""
    props = result.get("properties", {}) or {}
    for key in ("confidence", "precision_score"):
        v = props.get(key)
        if isinstance(v, (int, float)):
            return max(0.0, min(1.0, float(v)))
    return 1.0


def prioritise(doc: dict[str, Any]) -> list[PrioritisedFinding]:
    """Turn a parsed PyraSec SARIF document into ranked, STRIDE-tagged findings.

    threat_score = base_severity * confidence * max(weight over mapped STRIDE
    categories). Using the *max* category weight means a finding that enables
    Elevation of Privilege is ranked by that worst outcome, not diluted by a
    milder co-category.
    """
    out: list[PrioritisedFinding] = []
    for res, _run in _iter_sarif_results(doc):
        rule_id = str(res.get("ruleId", "UNKNOWN"))
        msg = sarif_text((res.get("message", {}) or {}).get("text", ""))
        level = str(res.get("level", "warning")).lower()
        base = _LEVEL_WEIGHT.get(level, 0.6)
        conf = _confidence_of(res)
        stride = map_finding(rule_id, msg)
        top = max((category_weight(c) for c in stride.categories), default=0.3)
        score = round(base * conf * top, 4)
        out.append(
            PrioritisedFinding(
                rule_id=rule_id,
                message=msg,
                level=level,
                location=_location_of(res),
                stride=stride,
                base_weight=base,
                threat_score=score,
                properties={
                    "pyrastride/strideCategories": list(stride.categories),
                    "pyrastride/threatScore": score,
                    "pyrastride/mappedOn": stride.matched_on,
                    "security-severity": f"{score * 10:.1f}",
                },
            )
        )
    out.sort(key=lambda f: -f.threat_score)
    return out


def to_sarif(findings: list[PrioritisedFinding], *, tool_version: str = "0.1.0") -> dict[str, Any]:
    """Emit a STRIDE-annotated SARIF 2.1.0 document from prioritised findings."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        primary = f.stride.categories[0]
        rid = make_sarif_rule_id("STRIDE", primary)
        rules.setdefault(
            rid,
            {
                "id": rid,
                "name": primary.title().replace("_", ""),
                "shortDescription": {"text": f"STRIDE: {primary.replace('_', ' ').title()}"},
            },
        )
        results.append(
            {
                "ruleId": rid,
                "level": f.level,
                "message": {"text": f"[{f.rule_id}] {f.message}"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": f.location.split(':')[0]}}}
                ],
                "properties": f.properties,
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PyraStride",
                        "version": tool_version,
                        "informationUri": "https://github.com/Kanak234/pyrastride",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def remediation_plan(findings: list[PrioritisedFinding], top_n: int = 20) -> str:
    """A human-readable, threat-ranked remediation plan (Markdown)."""
    lines = ["# PyraStride — threat-ranked remediation plan", ""]
    lines.append(f"{len(findings)} finding(s), ordered by threat score.\n")
    for i, f in enumerate(findings[:top_n], 1):
        cats = ", ".join(c.replace("_", " ").title() for c in f.stride.categories)
        lines.append(
            f"## {i}. `{f.rule_id}` — score {f.threat_score:.2f}\n"
            f"- **STRIDE:** {cats}\n"
            f"- **Where:** `{f.location}`\n"
            f"- **What:** {f.message[:200]}\n"
        )
    return "\n".join(lines)


def load_sarif(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
