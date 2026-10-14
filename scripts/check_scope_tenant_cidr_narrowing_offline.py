"""Offline narrowing check of two self-declared, disjoint tenant CIDR inventories.

This is a non-authorizing textual relationship, NOT an authenticated scope,
trusted previous state, asset ownership, client consent, grant or permit.
"""
from __future__ import annotations

import json
import sys

try:
    from scripts.check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _network, _result, parse_json, review_network_inventory,
    )
except ModuleNotFoundError:  # direct scripts/ invocation
    from check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _network, _result, parse_json, review_network_inventory,
    )


def review_tenant_narrowing(document: object) -> dict[str, object]:
    if (type(document) is not dict
            or set(document) != {"schema_version", "previous", "proposed"}
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1):
        return _result("HOLD", "INVALID_TRANSITION_SHAPE")
    previous, proposed = document["previous"], document["proposed"]

    # Check both complete documents, not only changed entries. A malicious
    # unchanged record could otherwise hide invalid/overlapping inventory.
    if review_network_inventory(previous)["status"] != "REVIEW_ONLY":
        return _result("HOLD", "INVALID_PREVIOUS_INVENTORY")
    if review_network_inventory(proposed)["status"] != "REVIEW_ONLY":
        return _result("HOLD", "INVALID_PROPOSED_INVENTORY")

    before = {(row["tenant_id"], row["scope_id"]): _network(row["cidr"])
              for row in previous["networks"]}
    after = {(row["tenant_id"], row["scope_id"]): _network(row["cidr"])
             for row in proposed["networks"]}
    if not set(after).issubset(before):
        # No new labels or reallocation to a different tenant under the same
        # scope name; all proposals can only narrow or drop existing scopes.
        return _result("HOLD", "NEW_OR_REASSIGNED_SCOPE")

    for key, network in after.items():
        old = before[key]
        if network.version != old.version or not network.subnet_of(old):
            return _result("HOLD", "WIDENED_OR_CHANGED_NETWORK")
    return _result("REVIEW_ONLY", "SAME_TENANT_NETWORK_NARROWING_SHAPE_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        receipt = _result("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        try:
            receipt = review_tenant_narrowing(
                parse_json(sys.stdin.buffer.read(MAX_BYTES + 1)))
        except ValueError:
            receipt = _result("HOLD", "INVALID_TRANSITION_JSON")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
