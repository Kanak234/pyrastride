# PyraStride

**Turn a flat list of security-scanner findings into a threat-model view.**

PyraStride reads the SARIF output of [PyraSec](https://github.com/Kanak234/PyraSec)
— a static security scanner — and re-frames every finding as a **STRIDE** threat
(Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service,
Elevation of Privilege). It then re-ranks findings by *what an attacker gains*,
not by raw severity, and emits both a STRIDE-annotated SARIF file and a
threat-ranked remediation plan.

A scanner tells you *what is wrong*. PyraStride tells you *which wrong thing an
attacker reaches first*.

## Why

PyraSec already grades findings by severity and confidence. But two "high"
findings are not equal: a hard-coded cloud key (an attacker gains privilege) and
a missing audit log (an attacker gains deniability) are different threats.
PyraStride adds the missing axis — the STRIDE category — and prioritises with it.

## Usage

```bash
# 1. run PyraSec, producing SARIF
pyrasec scan ./myproject --export sarif --out findings.sarif

# 2. bridge it into a STRIDE threat model
pyrastride findings.sarif                       # prints the remediation plan
pyrastride findings.sarif --out sarif           # prints STRIDE-annotated SARIF
pyrastride findings.sarif --out both \
    --sarif-out stride.sarif --plan-out plan.md
```

The emitted SARIF carries a `security-severity` property, so it uploads cleanly
to GitHub code scanning and sorts there by threat score.

## Install

```bash
pip install -e ".[dev]"     # dev extras add pytest + ruff
```

No runtime dependencies — pure standard library. Python 3.9+.

## How it works

| Stage | Module | Origin |
|---|---|---|
| Parse PyraSec SARIF | `bridge.py` | original |
| Map finding → STRIDE category | `stride_map.py` | original |
| Threat-weighted prioritisation | `bridge.py` | original |
| Emit STRIDE SARIF + plan | `bridge.py` | original |
| SARIF ruleId sanitisation | `sarif_helpers.py` | adapted from stride-gpt (see below) |

`threat_score = base_severity × confidence × max(STRIDE category weight)`. Using
the **max** category weight means a finding is ranked by its worst outcome, not
diluted by a milder co-category.

## Attribution

PyraStride reuses a small, well-tested piece of SARIF ruleId sanitisation from
**[stride-gpt](https://github.com/mrwadams/stride-gpt)** by Matt Adams (MIT,
© 2024). That is the *only* third-party code here — stride-gpt's LLM engine, UI,
and pipeline are **not** used. Full details, and the preserved upstream license,
are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and
[`LICENSE.stride-gpt`](LICENSE.stride-gpt). Nothing here is presented as original
that is not.

## License

MIT — see [`LICENSE`](LICENSE).
