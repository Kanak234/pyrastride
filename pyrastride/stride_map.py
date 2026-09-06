"""Map PyraSec static-scan findings to STRIDE threat categories.

Original work. PyraSec (the author's own static security scanner) groups its
rules into modules — secrets, containers, iac, gitops, filesystem, webserver,
dependencies — and tags every SARIF result with a ruleId like ``SEC001`` and a
rule "kind". STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure,
Denial of Service, Elevation of Privilege) is a threat-modelling taxonomy.

Neither PyraSec nor stride-gpt contains this mapping; it is the core new idea of
PyraStride — turning a flat list of scanner findings into a threat-model view so
they can be triaged by *what an attacker gains*, not just by raw severity.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# The six STRIDE categories, with a defensible risk weight used by the
# prioritiser. Elevation of Privilege sits highest because it is the category an
# attacker most wants to reach; Repudiation lowest because it rarely enables
# direct compromise on its own. These weights are a starting policy, not a law —
# they live here so they can be tuned in one place.
STRIDE = {
    "SPOOFING": 0.70,
    "TAMPERING": 0.85,
    "REPUDIATION": 0.50,
    "INFORMATION_DISCLOSURE": 0.80,
    "DENIAL_OF_SERVICE": 0.60,
    "ELEVATION_OF_PRIVILEGE": 1.00,
}

# PyraSec rule module / kind  ->  the STRIDE categories it implies.
# Keyed by lowercase substrings matched against a finding's rule kind, module
# tag, or message, most-specific first.
_RULES: list[tuple[str, tuple[str, ...]]] = [
    # leaked credentials: an attacker reads a secret (disclosure) and then uses
    # it to act as someone with more rights (elevation).
    ("secret", ("INFORMATION_DISCLOSURE", "ELEVATION_OF_PRIVILEGE")),
    ("token", ("INFORMATION_DISCLOSURE", "ELEVATION_OF_PRIVILEGE")),
    ("key", ("INFORMATION_DISCLOSURE", "ELEVATION_OF_PRIVILEGE")),
    ("password", ("INFORMATION_DISCLOSURE", "ELEVATION_OF_PRIVILEGE")),
    ("private key", ("INFORMATION_DISCLOSURE", "ELEVATION_OF_PRIVILEGE")),
    # privileged containers / pods: the classic path to host takeover.
    ("privileged", ("ELEVATION_OF_PRIVILEGE", "TAMPERING")),
    ("container", ("ELEVATION_OF_PRIVILEGE", "TAMPERING")),
    ("pod", ("ELEVATION_OF_PRIVILEGE", "TAMPERING")),
    # infrastructure-as-code misconfig: attacker changes infra state.
    ("iac", ("TAMPERING", "ELEVATION_OF_PRIVILEGE")),
    ("terraform", ("TAMPERING", "ELEVATION_OF_PRIVILEGE")),
    ("firewall", ("TAMPERING", "ELEVATION_OF_PRIVILEGE")),
    ("public", ("INFORMATION_DISCLOSURE", "ELEVATION_OF_PRIVILEGE")),
    # git / CI: tampering with the pipeline, and covering tracks.
    ("gitops", ("TAMPERING", "REPUDIATION")),
    ("workflow", ("TAMPERING", "REPUDIATION")),
    ("ci", ("TAMPERING", "REPUDIATION")),
    # logging disabled: you can't prove who did what.
    ("logging", ("REPUDIATION",)),
    ("audit", ("REPUDIATION",)),
    # filesystem: readable/writable where it shouldn't be.
    ("permission", ("INFORMATION_DISCLOSURE", "TAMPERING")),
    ("world-writable", ("TAMPERING",)),
    ("backup", ("INFORMATION_DISCLOSURE",)),
    # webserver: headers/tls/cors weaknesses.
    ("cors", ("SPOOFING", "INFORMATION_DISCLOSURE")),
    ("tls", ("SPOOFING", "INFORMATION_DISCLOSURE")),
    ("header", ("SPOOFING", "TAMPERING")),
    ("cookie", ("SPOOFING", "INFORMATION_DISCLOSURE")),
    # vulnerable / outdated dependencies.
    ("dependency", ("TAMPERING", "ELEVATION_OF_PRIVILEGE")),
    ("outdated", ("TAMPERING", "ELEVATION_OF_PRIVILEGE")),
    ("cve", ("TAMPERING", "ELEVATION_OF_PRIVILEGE")),
]


@dataclass(frozen=True)
class StrideMatch:
    categories: tuple[str, ...]
    matched_on: str  # which keyword triggered the mapping (for transparency)


def map_finding(*text_fields: str) -> StrideMatch:
    """Map one finding to STRIDE categories.

    Pass any text that describes the finding — its rule kind, module, message,
    ruleId. The first keyword that matches wins; if nothing matches, the finding
    is left ``UNKNOWN`` rather than force-fitted into a category (a wrong
    threat label is worse than an honest "unclassified").
    """
    haystack = " ".join(t for t in text_fields if t).lower()
    for needle, cats in _RULES:
        # word-boundary match so "key" does not fire on "keywords"/"monkey"
        # and "ci" does not fire on "specification".
        pattern = r"\b" + re.escape(needle) + r"\b"
        if re.search(pattern, haystack):
            return StrideMatch(cats, needle)
    return StrideMatch(("UNKNOWN",), "")


def category_weight(category: str) -> float:
    """Risk weight for a STRIDE category; UNKNOWN gets a low, non-zero floor."""
    return STRIDE.get(category, 0.30)
