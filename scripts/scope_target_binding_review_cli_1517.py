#!/usr/bin/env python3
"""Offline-only #1517 fictional target-binding drift JSON reviewer.

Explicit manual stdin; never opens files, connects sockets, scans, creates
grants or emits affirmative authority. Exit 2=fictional review, 3=HOLD; never 0.
"""
from __future__ import annotations

import json
import sys

from lightup.scope_target_binding_review_1517 import review_target_binding_batch_1517

_MAX_BYTES = 16384
_FLAGS = ',"authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}'


def _duplicates_forbidden(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _forbid_constant(value):
    raise ValueError("non-RFC constant")


def _evaluate(payload: bytes) -> str:
    if not payload or len(payload) > _MAX_BYTES or b"\\x00" in payload:
        return "HOLD"
    try:
        data = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_duplicates_forbidden,
            parse_constant=_forbid_constant,
        )
        if type(data) is not dict or tuple(data) != ("pairs",):
            return "HOLD"
        # Strict compact canonical serialization blocks whitespace, Unicode
        # aliases, duplicate keys, floats with non-RFC constants and reordering.
        if json.dumps(
            data, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        ).encode("ascii") != payload:
            return "HOLD"
        raw_pairs = data["pairs"]
        if type(raw_pairs) is not list or not 1 <= len(raw_pairs) <= 64:
            return "HOLD"
        pairs = []
        for pair in raw_pairs:
            if type(pair) is not list or len(pair) != 2:
                return "HOLD"
            if any(type(rec) is not list or len(rec) != 4 for rec in pair):
                return "HOLD"
            pairs.append((tuple(pair[0]), tuple(pair[1])))
        return review_target_binding_batch_1517(tuple(pairs)).status
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        return "HOLD"


def main() -> int:
    try:
        payload = sys.stdin.buffer.read(_MAX_BYTES + 1)
        status = _evaluate(payload)
    except (OSError, ValueError, TypeError):
        status = "HOLD"
    if status != "REVIEW_ONLY":
        status = "HOLD"
    sys.stdout.write('{"status":"' + status + '"' + _FLAGS + "\n")
    return 2 if status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
