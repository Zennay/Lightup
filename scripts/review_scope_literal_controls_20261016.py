#!/usr/bin/env python3
"""Bounded stdin-only fictional scope-text reviewer; NEVER an authorization CLI.

Exit 2 means REVIEW_ONLY; exit 3 means HOLD. There is no success exit 0.
No provided string is echoed, logged, persisted, resolved or contacted.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Resolve only this repository's module path, never a user-supplied location.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.scope_literal_control_review_20261016 import review_literals

_MAX_BYTES = 8192
_HOLD = b'{"status":"HOLD","authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}\n'
_REVIEW = b'{"status":"REVIEW_ONLY","authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}\n'


def _reject_constant(_value: str) -> object:
    raise ValueError("non-RFC JSON constant")


def _only_schema(pairs: list[tuple[str, object]]) -> object:
    if len(pairs) != 1 or pairs[0][0] != "authorities":
        raise ValueError("noncanonical JSON object")
    return {"authorities": pairs[0][1]}


def _read_bounded(stream: object) -> bytes:
    """Read to EOF, not to the first short read; never retain >8192 bytes."""
    chunks: list[bytes] = []
    total = 0
    while True:
        requested = min(1024, _MAX_BYTES - total + 1)
        chunk = stream.read(requested)
        if type(chunk) is not bytes or len(chunk) > requested:
            raise ValueError("invalid bounded input fragment")
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_BYTES:
            raise ValueError("bounded input required")
        chunks.append(chunk)
    if not total:
        raise ValueError("input required")
    return b"".join(chunks)


def main() -> int:
    try:
        raw = _read_bounded(sys.stdin.buffer)
        value = json.loads(
            raw.decode("ascii"), object_pairs_hook=_only_schema,
            parse_constant=_reject_constant,
        )
        values = value["authorities"]
        if type(values) is not list:
            raise ValueError("array required")
        # Exactly one canonical representation; no duplicate keys, trailing
        # whitespace, invisible aliases, formatting drift, or trailing bytes.
        encoded = json.dumps(
            {"authorities": values}, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if raw != encoded:
            raise ValueError("noncanonical byte sequence")
        result = review_literals(tuple(values))
        if result.status != "REVIEW_ONLY":
            raise ValueError("literal integrity HOLD")
    except (ValueError, TypeError, UnicodeError, KeyError, RecursionError, OverflowError, OSError):
        sys.stdout.buffer.write(_HOLD)
        return 3
    sys.stdout.buffer.write(_REVIEW)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
