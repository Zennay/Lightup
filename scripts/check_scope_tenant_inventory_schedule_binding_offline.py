"""Offline, non-authorizing cross-binding of declared lab CIDRs and UTC windows.

The input is fully caller-controlled. Consistent text is NEVER evidence of
tenant ownership, legal consent, trusted grant, routing isolation or permit.
"""
from __future__ import annotations

import json
import sys

try:
    from scripts.check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _result, parse_json, review_network_inventory,
    )
    from scripts.check_scope_tenant_window_conflicts_offline import review_window_plan
except ModuleNotFoundError:
    from check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _result, parse_json, review_network_inventory,
    )
    from check_scope_tenant_window_conflicts_offline import review_window_plan


def review_inventory_schedule_binding(document: object) -> dict[str, object]:
    if (type(document) is not dict
            or set(document) != {"schema_version", "inventory", "schedule"}
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1):
        return _result("HOLD", "INVALID_BINDING_SHAPE")
    inventory, schedule = document["inventory"], document["schedule"]
    if review_network_inventory(inventory)["status"] != "REVIEW_ONLY":
        return _result("HOLD", "INVALID_INVENTORY")
    if review_window_plan(schedule)["status"] != "REVIEW_ONLY":
        return _result("HOLD", "INVALID_WINDOW_SCHEDULE")
    # Both component validators have already enforced types, 1–32 / 1–64
    # bounds, no duplicate tenant+scope, and canonical CIDR text.
    declared = {
        (record["tenant_id"], record["scope_id"], record["cidr"])
        for record in inventory["networks"]
    }
    scheduled = {
        (record["tenant_id"], record["scope_id"], record["cidr"])
        for record in schedule["windows"]
    }
    # Whole-scope bijection: no "extra" tenant, alias, changed CIDR or
    # unplanned inventory record may be silently ignored.
    if declared != scheduled:
        return _result("HOLD", "INVENTORY_SCHEDULE_MISMATCH")
    return _result("REVIEW_ONLY", "CROSS_BOUND_UNTRUSTED_PLAN_SHAPES_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        receipt = _result("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        try:
            receipt = review_inventory_schedule_binding(parse_json(
                sys.stdin.buffer.read(MAX_BYTES + 1)))
        except ValueError:
            receipt = _result("HOLD", "INVALID_BINDING_JSON")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
