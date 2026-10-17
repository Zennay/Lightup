#!/usr/bin/env python3
"""Opt-in stdin-only synthetic ToolOutput shape review (#1533).

This CLI is NOT a consent, approval, scan, evidence-provenance or execution
interface. No files, sockets, StateStore or tool handlers are consulted.
Input schema: {"schema":"lightup.scope1533.synthetic.v1","synthetic_only":true,
"items":[{"summary":"Example","kind":"note","payload_hex":"00"}]}
Receipts never exit zero and never echo or persist input data.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.scope_tooloutput_shape_review_20261017 import (
    OutputIdentityReview,
    review_output_batch,
)

_SCHEMA = "lightup.scope1533.synthetic.v1"
_MAX_STDIN = 65_536
_MAX_CONTAINERS = 34  # root dict + items list + up to 32 item dicts
_HEX = re.compile(r"[0-9a-f]*\Z", re.ASCII)


def _duplicate_free_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON field")
        obj[key] = value
    return obj


def _deny_numeric(_token: str) -> None:
    raise ValueError("numeric fields are not part of the schema")


def _preflight(raw: bytes) -> None:
    """Bound container depth/count before json.loads; ignore quoted braces."""
    depth = 0
    containers = 0
    quoted = False
    escape = False
    for byte in raw:
        if quoted:
            if escape:
                escape = False
            elif byte == 92:
                escape = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            containers += 1
            if depth > 3 or containers > _MAX_CONTAINERS:
                raise ValueError("invalid resource shape")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise ValueError("invalid resource shape")
    if quoted or depth:
        raise ValueError("invalid resource shape")


def _parse_synthetic(raw: bytes) -> tuple[tuple[str, str, bytes], ...]:
    if not raw or len(raw) > _MAX_STDIN:
        raise ValueError("invalid input length")
    _preflight(raw)
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_duplicate_free_object,
        parse_int=_deny_numeric,
        parse_float=_deny_numeric,
        parse_constant=_deny_numeric,
    )
    if type(value) is not dict or set(value) != {"schema", "synthetic_only", "items"}:
        raise ValueError("unexpected envelope")
    if value["schema"] != _SCHEMA or value["synthetic_only"] is not True:
        raise ValueError("not a synthetic envelope")
    items = value["items"]
    if type(items) is not list or not 1 <= len(items) <= 32:
        raise ValueError("invalid item count")
    parsed = []
    for item in items:
        if type(item) is not dict or set(item) != {"summary", "kind", "payload_hex"}:
            raise ValueError("unexpected item")
        summary, kind, payload_hex = item["summary"], item["kind"], item["payload_hex"]
        if type(summary) is not str or type(kind) is not str or type(payload_hex) is not str:
            raise ValueError("invalid value type")
        if len(payload_hex) % 2 or len(payload_hex) > _MAX_STDIN or not _HEX.fullmatch(payload_hex):
            raise ValueError("noncanonical payload encoding")
        parsed.append((summary, kind, bytes.fromhex(payload_hex)))
    return tuple(parsed)


def main(args: list[str]) -> int:
    result = OutputIdentityReview.HOLD
    if type(args) is list and not args:
        try:
            raw = sys.stdin.buffer.read(_MAX_STDIN + 1)
            result = review_output_batch(_parse_synthetic(raw))
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
            pass
    response = {
        "schema": "lightup.scope1533.receipt.v1",
        "status": result.value,
        "authorization_verified": False,
        "consent_verified": False,
        "permit_issued": False,
        "dispatch_allowed": False,
        "execution_enabled": False,
        "merge_approved": False,
        "release_approved": False,
    }
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if result is OutputIdentityReview.REVIEW_ONLY else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
