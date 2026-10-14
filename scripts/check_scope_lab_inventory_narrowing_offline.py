"""Read-only shape-only check that a proposed lab-literal set never widens.

The two snapshots are caller-controlled text and cannot establish trusted
history, consent, host ownership, authorization, or a release decision.
"""
from __future__ import annotations

import json
import sys

try:
    from scripts.check_scope_lab_inventory_offline import (
        MAX_MANIFEST_BYTES, _canonical_literally_reviewable, _receipt,
        parse_document,
    )
except ModuleNotFoundError:  # standalone python3 scripts/ invocation
    from check_scope_lab_inventory_offline import (
        MAX_MANIFEST_BYTES, _canonical_literally_reviewable, _receipt,
        parse_document,
    )


def review_narrowing(document: object) -> dict[str, object]:
    """Require the proposed IP-literal set to be a subset of the prior set.

    No real assets or prior state are queried, and both are untrusted JSON.
    REVIEW_ONLY is only a syntactic consistency observation, not an approval.
    """
    if (
        type(document) is not dict
        or set(document) != {
            "schema_version", "previous_lab_literals", "proposed_lab_literals"
        }
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
    ):
        return _receipt("HOLD", "INVALID_TRANSITION_SHAPE")
    try:
        previous = _canonical_literally_reviewable(document["previous_lab_literals"])
        proposed = _canonical_literally_reviewable(document["proposed_lab_literals"])
    except (ValueError, TypeError, AttributeError, OverflowError):
        return _receipt("HOLD", "INVALID_LAB_LITERAL")
    if not proposed.issubset(previous):
        return _receipt("HOLD", "SCOPE_WIDENING")
    return _receipt("REVIEW_ONLY", "NO_WIDENING_SHAPE_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = _receipt("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        raw = sys.stdin.buffer.read(MAX_MANIFEST_BYTES + 1)
        try:
            result = review_narrowing(parse_document(raw))
        except ValueError:
            result = _receipt("HOLD", "INVALID_TRANSITION_JSON")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # Never permit an untrusted prior snapshot to become a shell success token.
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
