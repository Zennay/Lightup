#!/usr/bin/env python3
"""Opt-in atomic fictional LAB capability cohort CLI (#1511), never authority.

Strict 4096-byte canonical JSON with generic HOLD/REVIEW_ONLY stdout.
Both single and batch CLIs use one shared no-I/O decoder.
"""
from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.fictional_lab_capability_batch_1511 import (
    review_fictional_lab_capability_cohort_1511,
)
from fictional_lab_capability_json_1511 import (
    _MAX_BYTES, parse_fictional_envelope_1511,
)

_SCHEMA = "fictional_lab_capability_batch_v1"


def decide_batch_stdin_bytes_1511(data: object) -> str:
    parsed = parse_fictional_envelope_1511(
        data, expected_schema=_SCHEMA, requested_type=list,
    )
    if parsed is None:
        return "HOLD"
    return review_fictional_lab_capability_cohort_1511(
        tuple(parsed["requested"]), tuple(parsed["allowlist"])
    ).status


def main() -> int:
    result = decide_batch_stdin_bytes_1511(sys.stdin.buffer.read(_MAX_BYTES + 1))
    sys.stdout.write(result + "\n")
    return 2 if result == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
