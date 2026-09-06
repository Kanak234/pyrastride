"""PyraStride command-line interface. Original work."""
from __future__ import annotations

import argparse
import json
import sys

from .bridge import load_sarif, prioritise, remediation_plan, to_sarif


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="pyrastride",
        description="Bridge PyraSec SARIF findings into a STRIDE threat-model view.",
    )
    p.add_argument("sarif", help="Path to a PyraSec SARIF file")
    p.add_argument("--out", choices=["sarif", "plan", "both"], default="plan",
                   help="Emit STRIDE-annotated SARIF, a remediation plan, or both")
    p.add_argument("--sarif-out", help="Write SARIF here (default: stdout)")
    p.add_argument("--plan-out", help="Write the plan here (default: stdout)")
    p.add_argument("--top", type=int, default=20, help="How many findings in the plan")
    args = p.parse_args(argv)

    try:
        doc = load_sarif(args.sarif)
    except (OSError, json.JSONDecodeError) as e:
        print(f"pyrastride: cannot read SARIF: {e}", file=sys.stderr)
        return 2

    findings = prioritise(doc)

    def _emit(text: str, path: str | None) -> None:
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        else:
            print(text)

    if args.out in ("sarif", "both"):
        _emit(json.dumps(to_sarif(findings), indent=2), args.sarif_out)
    if args.out in ("plan", "both"):
        _emit(remediation_plan(findings, top_n=args.top), args.plan_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
