"""Offline review of *each* narrowing step in an untrusted lab-inventory sequence.

A later revert does not conceal an earlier scope expansion. Submitted
versions are untrusted content, not a complete or authenticated history.
"""
from __future__ import annotations

import json
import sys

try:
    from scripts.check_scope_lab_inventory_offline import (
        MAX_MANIFEST_BYTES, _canonical_literally_reviewable,
        _receipt, parse_document,
    )
except ModuleNotFoundError:  # standalone python3 scripts/ invocation
    from check_scope_lab_inventory_offline import (
        MAX_MANIFEST_BYTES, _canonical_literally_reviewable,
        _receipt, parse_document,
    )


def review_history(document: object) -> dict[str, object]:
    """Require monotonic narrowing across every supplied version (2–4).

    Caller controls version list and ordering. REVIEW_ONLY never authenticates
    chronology, consent, ownership, or trusted previous snapshots.
    """
    if (
        type(document) is not dict
        or set(document) != {"schema_version", "lab_literal_versions"}
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
    ):
        return _receipt("HOLD", "INVALID_HISTORY_SHAPE")
    versions = document["lab_literal_versions"]
    if type(versions) is not list or not (2 <= len(versions) <= 4):
        return _receipt("HOLD", "INVALID_HISTORY_LENGTH")
    try:
        previous = _canonical_literally_reviewable(versions[0])
        for version in versions[1:]:
            current = _canonical_literally_reviewable(version)
            if not current.issubset(previous):
                return _receipt("HOLD", "TRANSIENT_SCOPE_WIDENING")
            previous = current
    except (ValueError, TypeError, AttributeError, OverflowError):
        return _receipt("HOLD", "INVALID_HISTORY_LITERAL")
    return _receipt("REVIEW_ONLY", "HISTORY_SHAPE_NARROW_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = _receipt("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        raw = sys.stdin.buffer.read(MAX_MANIFEST_BYTES + 1)
        try:
            result = review_history(parse_document(raw))
        except ValueError:
            result = _receipt("HOLD", "INVALID_HISTORY_JSON")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # Neither a HOLD nor a reviewable text series ever grants shell success.
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
