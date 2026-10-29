"""Recheck a saved batch receipt against current private inputs.

This is a read-only byte-consistency check. It never authenticates a receipt or
promotes HOLD into a security, authorization, consent, or release decision.
"""
from __future__ import annotations

import json
import secrets
import sys

import batch
from receipt import (
    FALSE_FLAGS,
    _finite_float,
    _read_private_regular,
    _reject_constant,
    _unique_pairs,
)

RECHECK_FORMAT = "lightup-offline-receipt-batch-recheck-v1"


def _hold() -> dict:
    return {
        "receipt_format": RECHECK_FORMAT,
        "status": "HOLD",
        "receipt_authenticated": False,
        "manifest_authenticated": False,
        "source_authenticated": False,
        "source_schema_verified": False,
        "receipt_matches_current_inputs": False,
        **{flag: False for flag in FALSE_FLAGS},
    }


def recheck(receipt_path, manifest_path, expected_manifest_sha256) -> dict:
    """Return a minimal HOLD result; disclose no source details on mismatch."""
    result = _hold()
    try:
        saved_bytes = _read_private_regular(receipt_path)
        saved = json.loads(
            saved_bytes.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        if type(saved) is not dict:
            return result

        current = batch.inspect_batch(manifest_path, expected_manifest_sha256)
        if current.get("byte_expectations_match") is not True:
            return result

        # Canonical JSON comparison is type-sensitive (e.g. true != 1), rejects
        # extra keys, and is independent of insignificant whitespace in storage.
        saved_canonical = json.dumps(
            saved, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        current_canonical = json.dumps(
            current, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        if secrets.compare_digest(saved_canonical, current_canonical):
            result["receipt_matches_current_inputs"] = True
    except (OSError, ValueError, UnicodeError, TypeError,
            RecursionError, OverflowError):
        return result
    return result


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 3:
        result = recheck(args[0], args[1], args[2])
    else:
        result = _hold()
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(3)
