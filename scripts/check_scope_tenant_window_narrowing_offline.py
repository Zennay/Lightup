"""Offline, non-authorizing tenant test-window and network narrowing review.

Never trust the previous plan as authenticated; a clean text comparison
proves neither valid grant, time-window consent nor safe target execution.
"""
from __future__ import annotations

import json
import sys

try:
    from scripts.check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _result, parse_json,
    )
    from scripts.check_scope_tenant_window_conflicts_offline import (
        _parsed, review_window_plan,
    )
except ModuleNotFoundError:
    from check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _result, parse_json,
    )
    from check_scope_tenant_window_conflicts_offline import (
        _parsed, review_window_plan,
    )


def review_window_narrowing(document: object) -> dict[str, object]:
    if (type(document) is not dict
            or set(document) != {"schema_version", "previous", "proposed"}
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1):
        return _result("HOLD", "INVALID_TRANSITION_SHAPE")

    previous = document["previous"]
    proposed = document["proposed"]
    if review_window_plan(previous)["status"] != "REVIEW_ONLY":
        return _result("HOLD", "INVALID_PREVIOUS_WINDOW_PLAN")
    if review_window_plan(proposed)["status"] != "REVIEW_ONLY":
        return _result("HOLD", "INVALID_PROPOSED_WINDOW_PLAN")

    # Both have already been exact-shape validated including keys and windows.
    old = {key: (net, start, end) for key, net, start, end in _parsed(previous)}
    new = {key: (net, start, end) for key, net, start, end in _parsed(proposed)}
    if not new.keys() <= old.keys():
        return _result("HOLD", "NEW_OR_REASSIGNED_WINDOW_SCOPE")

    for key, (net, start, end) in new.items():
        parent, first, last = old[key]
        if (parent.version != net.version
                or not net.subnet_of(parent)
                or start < first or end > last):
            return _result("HOLD", "EXPANDED_OR_MOVED_WINDOW")
    return _result("REVIEW_ONLY", "UNTRUSTED_WINDOW_NARROWING_SHAPE_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        receipt = _result("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        try:
            receipt = review_window_narrowing(
                parse_json(sys.stdin.buffer.read(MAX_BYTES + 1)))
        except ValueError:
            receipt = _result("HOLD", "INVALID_TRANSITION_JSON")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
