#!/usr/bin/env python3
"""Opt-in, fictional-only LAB capability review CLI (issue #1511).

Never exit 0 or execute tools. Neither REVIEW_ONLY nor HOLD is authorization.
Input is a *fictional* caller-provided set, NOT a trusted registry.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

# Explicit local source import only; never import installed runtime handlers.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.fictional_lab_capability_review_1511 import (
    review_fictional_lab_capability_1511,
)

_MAX_BYTES = 4096
_SCHEMA = "fictional_lab_capability_v1"


class _RejectJSON(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _RejectJSON("duplicate")
        result[key] = value
    return result


def decide_stdin_bytes_1511(data: object) -> str:
    """Return generic non-authority status. No original input is ever echoed."""
    if type(data) is not bytes or not (1 <= len(data) <= _MAX_BYTES):
        return "HOLD"
    try:
        raw = data.decode("ascii")
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        # Eliminate whitespace, escapes, duplicate encodings and alias fields.
        if type(parsed) is not dict or tuple(parsed) != ("schema", "requested", "allowlist"):
            return "HOLD"
        if json.dumps(parsed, ensure_ascii=True, separators=(",", ":")) != raw:
            return "HOLD"
        if parsed["schema"] != _SCHEMA or type(parsed["schema"]) is not str:
            return "HOLD"
        if type(parsed["allowlist"]) is not list:
            return "HOLD"
        result = review_fictional_lab_capability_1511(
            parsed["requested"], tuple(parsed["allowlist"])
        )
        return result.status
    except (ValueError, UnicodeError, TypeError, KeyError, RecursionError):
        return "HOLD"


def main() -> int:
    # Bounded standard-input-only read, no file writes, network or subprocess.
    # sys.stdin.buffer.read(n) waits for EOF on a pipe as needed.
    result = decide_stdin_bytes_1511(sys.stdin.buffer.read(_MAX_BYTES + 1))
    sys.stdout.write(result + "\n")
    return 2 if result == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
