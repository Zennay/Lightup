"""Offline non-authorizing multi-revision UTC lab window consistency review.

Every version is entirely self-declared and may omit past changes.
This is not a signed audit, actual authorization, consent or scan gate.
"""
from __future__ import annotations

import json
import sys

try:
    from scripts.check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _result, parse_json,
    )
    from scripts.check_scope_tenant_window_conflicts_offline import review_window_plan
    from scripts.check_scope_tenant_window_narrowing_offline import review_window_narrowing
except ModuleNotFoundError:
    from check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _result, parse_json,
    )
    from check_scope_tenant_window_conflicts_offline import review_window_plan
    from check_scope_tenant_window_narrowing_offline import review_window_narrowing


def review_window_history(document: object) -> dict[str, object]:
    if (type(document) is not dict
            or set(document) != {"schema_version", "versions"}
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1):
        return _result("HOLD", "INVALID_HISTORY_SHAPE")
    versions = document["versions"]
    if type(versions) is not list or not (2 <= len(versions) <= 4):
        return _result("HOLD", "INVALID_HISTORY_LENGTH")
    previous = None
    for current in versions:
        if review_window_plan(current)["status"] != "REVIEW_ONLY":
            return _result("HOLD", "INVALID_HISTORY_WINDOW_PLAN")
        if previous is not None and review_window_narrowing({
            "schema_version": 1,
            "previous": previous,
            "proposed": current,
        })["status"] != "REVIEW_ONLY":
            return _result("HOLD", "NONMONOTONIC_WINDOW_HISTORY")
        previous = current
    return _result("REVIEW_ONLY", "UNTRUSTED_NARROWING_WINDOW_HISTORY_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        r = _result("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        try:
            r = review_window_history(parse_json(
                sys.stdin.buffer.read(MAX_BYTES + 1)))
        except ValueError:
            r = _result("HOLD", "INVALID_HISTORY_JSON")
    print(json.dumps(r, sort_keys=True, separators=(",", ":")))
    return 3 if r["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
