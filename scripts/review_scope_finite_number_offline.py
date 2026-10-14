#!/usr/bin/env python3
"""Opt-in, stdin-only, non-authorizing finite NUMBER review for #1143.

Usage: python scripts/review_scope_finite_number_offline.py < synthetic.json
The input envelope is exactly {"arguments":[["name",1.25],...]}.
Outputs only a fixed privacy-minimal receipt; never exits 0.
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.finite_number_offline_review import review_finite_number_arguments

_MAX_INPUT_BYTES = 8192


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("nonfinite JSON token")


def _parse_exact_finite_json_float(token: str) -> float:
    """Deny nonzero JSON mantissas that Python rounds all the way to zero.

    Purely lexical protection against silently losing a nonzero quantity when
    parsing an offline numeric preview; this is not a production runtime gate.
    """
    result = float(token)
    if not math.isfinite(result):
        raise ValueError("invalid float boundary")
    mantissa = token.split("e", 1)[0].split("E", 1)[0]
    if result == 0.0 and any(char in "123456789" for char in mantissa):
        raise ValueError("rounded nonzero float to zero")
    return result


def main(args: list[str]) -> int:
    values: object = ()
    if type(args) is list and not args:
        try:
            raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
            if not raw or len(raw) > _MAX_INPUT_BYTES:
                raise ValueError("invalid size")
            obj = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_keys,
                parse_constant=_reject_constant,
                parse_float=_parse_exact_finite_json_float,
            )
            if type(obj) is not dict or set(obj) != {"arguments"}:
                raise ValueError("invalid envelope")
            rows = obj["arguments"]
            if type(rows) is not list or not 1 <= len(rows) <= 32:
                raise ValueError("invalid rows")
            if any(type(row) is not list or len(row) != 2 for row in rows):
                raise ValueError("invalid row")
            values = tuple((row[0], row[1]) for row in rows)
        except (UnicodeError, json.JSONDecodeError, TypeError, ValueError,
                OverflowError, RecursionError):
            values = ()
    receipt = review_finite_number_arguments(values)
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
