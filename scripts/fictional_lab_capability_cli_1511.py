#!/usr/bin/env python3
"""Opt-in fictional LAB capability review CLI (#1511); never a real permit.

Both canonical single/batch interfaces share one bounded strict JSON decoder.
No target interaction or trusted registry, even for REVIEW_ONLY / exit 2.
"""
from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.fictional_lab_capability_review_1511 import (
    review_fictional_lab_capability_1511,
)
from fictional_lab_capability_json_1511 import (
    _MAX_BYTES, parse_fictional_envelope_1511,
)

_SCHEMA = "fictional_lab_capability_v1"


def decide_stdin_bytes_1511(data: object) -> str:
    """Generic no-echo HOLD or fictional-only REVIEW_ONLY, never authorization."""
    parsed = parse_fictional_envelope_1511(
        data, expected_schema=_SCHEMA, requested_type=str,
    )
    if parsed is None:
        return "HOLD"
    return review_fictional_lab_capability_1511(
        parsed["requested"], tuple(parsed["allowlist"])
    ).status


def main() -> int:
    result = decide_stdin_bytes_1511(sys.stdin.buffer.read(_MAX_BYTES + 1))
    sys.stdout.write(result + "\n")
    return 2 if result == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
