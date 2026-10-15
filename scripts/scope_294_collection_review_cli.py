"""Strictly offline issue #294 scope-collection metadata review.

Usage:
  printf '{"hosts":["fixture.example.test"],"networks":["8.8.8.0/24"]}' |
    python scripts/scope_294_collection_review_cli.py

No target scans, grants, tools, external requests, or 0 exit codes.
Exit 2: HOLD; exit 3: REVIEW_ONLY (never authorization).
"""
from __future__ import annotations

import json
import os
import sys

# Use the checked-out project source; never import another installation first.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.scope_collection_snapshot_review_294 import (
    ScopeCollectionReview,
    snapshot_untrusted_scope_collections,
)

_MAX_INPUT_BYTES = 16 * 1024


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate input key")
        output[key] = value
    return output


def _reject_nonfinite(_value: str) -> object:
    raise ValueError("nonfinite JSON values are not allowed")


def review_private_manifest(raw: bytes) -> ScopeCollectionReview:
    """Input is wholly untrusted, and even REVIEW_ONLY confers no authority."""
    if type(raw) is not bytes or len(raw) > _MAX_INPUT_BYTES:
        return ScopeCollectionReview("HOLD", "invalid_collections")
    try:
        decoded = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (ValueError, UnicodeError, RecursionError):
        return ScopeCollectionReview("HOLD", "invalid_collections")
    if type(decoded) is not dict or set(decoded) != {"hosts", "networks"}:
        return ScopeCollectionReview("HOLD", "invalid_collections")
    # JSON arrays must not be silently converted from strings or objects.
    if type(decoded["hosts"]) is not list or type(decoded["networks"]) is not list:
        return ScopeCollectionReview("HOLD", "invalid_collections")
    return snapshot_untrusted_scope_collections(decoded["hosts"], decoded["networks"])


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
        review = review_private_manifest(raw)
    except (OSError, ValueError):
        review = ScopeCollectionReview("HOLD", "invalid_collections")
    print(json.dumps(review.to_public_dict(), sort_keys=True, separators=(",", ":")))
    return 3 if review.status == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
