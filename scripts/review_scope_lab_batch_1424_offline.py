#!/usr/bin/env python3
"""Strict offline *batch review* for synthetic lab IP literals (#1424).

This is NOT scope authorization. Neither REVIEW_ONLY nor HOLD issues a permit.
Never performs target/DNS/HTTP I/O, writes a file or exits with success (0).
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.scope_lab_literal_review_1424 import review_lab_literal


_MAX_INPUT_BYTES = 4096
_MAX_LITERALS = 16


def _distinct_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Do not silently normalize ambiguous repeated JSON keys."""
    found: dict[str, object] = {}
    for key, value in pairs:
        if key in found:
            raise ValueError("ambiguous JSON object")
        found[key] = value
    return found


def _deny_nonfinite(_literal: str) -> object:
    raise ValueError("nonfinite JSON")


def review_batch_json(raw: object) -> tuple[str, int]:
    """Review a complete bounded in-memory batch, atomically.

    Return a display-only status and number of reviewed inputs.
    The *only* caller who may use the result is an offline reviewer;
    it must never be interpreted as an active scope or grant decision.
    """
    if type(raw) is not bytes or not raw or len(raw) > _MAX_INPUT_BYTES:
        return "HOLD", 0
    try:
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_distinct_object,
            parse_constant=_deny_nonfinite,
        )
    except (UnicodeError, ValueError, RecursionError, TypeError):
        return "HOLD", 0
    if type(document) is not dict or set(document) != {"literals"}:
        return "HOLD", 0
    literals = document["literals"]
    if type(literals) is not list or not 1 <= len(literals) <= _MAX_LITERALS:
        return "HOLD", 0
    # Atomic HOLD: even one unknown, duplicated, or polymorphic member
    # prevents the batch being characterized as wholly reviewable.
    unique: set[str] = set()
    for literal in literals:
        if type(literal) is not str or literal in unique:
            return "HOLD", 0
        unique.add(literal)
        if review_lab_literal(literal).status != "REVIEW_ONLY":
            return "HOLD", 0
    return "REVIEW_ONLY", len(literals)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    status, count = "HOLD", 0
    if (type(arguments) is list and len(arguments) == 1
            and type(arguments[0]) is str and arguments[0] == "--stdin-json"):
        try:
            raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
            status, count = review_batch_json(raw)
        except (OSError, ValueError):
            status, count = "HOLD", 0
    # Fresh literal booleans each run: never use a mutable shared dictionary
    # that a previous call could poison into asserting a forged permission.
    receipt = {
        "status": status,
        "reviewed_count": count,
        "authorization_verified": False,
        "permit_issued": False,
        "execution_enabled": False,
        "merge_approved": False,
        "release_approved": False,
    }
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    # All statuses are nonzero: review-only is not operational authority.
    return 3 if status == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
