"""SARIF string helpers.

The two functions ``_make_sarif_rule_id`` and ``sarif_text`` in this module are
adapted, largely verbatim, from stride-gpt by Matt Adams
(https://github.com/mrwadams/stride-gpt, MIT License, Copyright (c) 2024 Matt
Adams — see THIRD_PARTY_NOTICES.md). They are reused here because SARIF ruleId
sanitisation is a solved, well-tested problem and there is no reason to write it
again. Everything else in PyraStride is original work.
"""
from __future__ import annotations

import re
from typing import Any

# --- begin: adapted from stride-gpt (MIT, (c) 2024 Matt Adams) ---------------

_SARIF_MESSAGE_MAX = 5000


def sarif_text(value: Any) -> str:
    """Coerce a value to a length-bounded string for a SARIF message."""
    text = "" if value is None else str(value)
    if len(text) > _SARIF_MESSAGE_MAX:
        return text[:_SARIF_MESSAGE_MAX] + "…[truncated]"
    return text


def make_sarif_rule_id(prefix: str, category: str) -> str:
    """Build a stable SARIF ruleId, stripped to ``PREFIX/[A-Z0-9_]``.

    Adapted from stride-gpt's ``_make_sarif_rule_id``; generalised here to take
    the namespace prefix as an argument (upstream hard-codes ``STRIDE/``) so the
    same sanitisation guards PyraStride's own rule ids.
    """
    raw = ("" if category is None else str(category)).upper()
    cleaned = re.sub(r"[^A-Z0-9_]+", "_", raw).strip("_")
    if not cleaned:
        cleaned = "UNKNOWN"
    return f"{prefix}/" + cleaned[:64]

# --- end: adapted from stride-gpt --------------------------------------------
