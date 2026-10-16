#!/usr/bin/env python3
"""Standalone fictitious LAB capability *batch* input review (#1511).

This opt-in stdin utility NEVER grants consent, scope, permits, dispatch or
release. Even a coherent fictitious batch is only REVIEW_ONLY, exit status 2.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.fictional_lab_capability_batch_1511 import (
    review_fictional_lab_capability_cohort_1511,
)
from fictional_lab_capability_cli_1511 import _reject_duplicate_keys

_MAX_BYTES = 4096
_SCHEMA = "fictional_lab_capability_batch_v1"


def decide_batch_stdin_bytes_1511(data: object) -> str:
    if type(data) is not bytes or not (1 <= len(data) <= _MAX_BYTES):
        return "HOLD"
    try:
        decoded = data.decode("ascii")
        data_object = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
        if type(data_object) is not dict:
            return "HOLD"
        if tuple(data_object) != ("schema", "requested", "allowlist"):
            return "HOLD"
        if json.dumps(data_object, ensure_ascii=True, separators=(",", ":")) != decoded:
            return "HOLD"
        if type(data_object["schema"]) is not str or data_object["schema"] != _SCHEMA:
            return "HOLD"
        if type(data_object["requested"]) is not list:
            return "HOLD"
        if type(data_object["allowlist"]) is not list:
            return "HOLD"
        result = review_fictional_lab_capability_cohort_1511(
            tuple(data_object["requested"]), tuple(data_object["allowlist"])
        )
        return result.status
    except (ValueError, UnicodeError, TypeError, KeyError, RecursionError):
        return "HOLD"


def main() -> int:
    # Only bounded stdin to EOF and one of two fixed generic stdout strings.
    status = decide_batch_stdin_bytes_1511(sys.stdin.buffer.read(_MAX_BYTES + 1))
    sys.stdout.write(status + "\n")
    return 2 if status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
