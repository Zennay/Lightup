"""Offline review of transient widening across supplied tenant lab CIDR versions.

Version history is untrusted, caller-controlled text; this is not a signed
audit log, authenticated inventory, grant, consent receipt or scan permission.
"""
from __future__ import annotations

import json
import sys

try:
    from scripts.check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _result, parse_json, review_network_inventory,
    )
    from scripts.check_scope_tenant_cidr_narrowing_offline import (
        review_tenant_narrowing,
    )
except ModuleNotFoundError:  # direct scripts/ entry
    from check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _result, parse_json, review_network_inventory,
    )
    from check_scope_tenant_cidr_narrowing_offline import review_tenant_narrowing


def review_tenant_network_history(document: object) -> dict[str, object]:
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
        if review_network_inventory(current)["status"] != "REVIEW_ONLY":
            return _result("HOLD", "INVALID_HISTORY_INVENTORY")
        if previous is not None:
            transition = {"schema_version": 1, "previous": previous,
                          "proposed": current}
            if review_tenant_narrowing(transition)["status"] != "REVIEW_ONLY":
                # An appended later revision cannot erase a temporary
                # expansion, added scope, ownership-label switch or overlap.
                return _result("HOLD", "NONMONOTONIC_TENANT_HISTORY")
        previous = current
    return _result("REVIEW_ONLY", "UNTRUSTED_NARROWING_HISTORY_SHAPE_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = _result("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        try:
            result = review_tenant_network_history(
                parse_json(sys.stdin.buffer.read(MAX_BYTES + 1)))
        except ValueError:
            result = _result("HOLD", "INVALID_HISTORY_JSON")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
