"""Offline, non-authorizing comparison of two fictional LightUp release reviews.

This compares only untrusted status claims. It cannot authenticate evidence,
infer readiness, or grant an operation from a reported change of state.
"""
from __future__ import annotations

import json
import sys

from scope_release_dependency_inventory_20261015 import (
    FLAGS, GATES, MAX_BYTES, InvalidPacket, _reject_constant,
    _unique_pairs, assess,
)
from scope_release_stdin_20261015 import read_bounded_stdin

TRANSITIONS = {
    ("MISSING", "MISSING"): "UNCHANGED",
    ("MISSING", "BLOCKED"): "NEW_BLOCKER",
    ("MISSING", "SELF_REPORTED"): "NEW_UNVERIFIED_CLAIM",
    ("BLOCKED", "MISSING"): "BLOCKER_REMOVED_UNVERIFIED",
    ("BLOCKED", "BLOCKED"): "UNCHANGED",
    ("BLOCKED", "SELF_REPORTED"): "NEW_UNVERIFIED_CLAIM",
    ("SELF_REPORTED", "MISSING"): "CLAIM_WITHDRAWN",
    ("SELF_REPORTED", "BLOCKED"): "CLAIM_WITHDRAWN_AND_BLOCKED",
    ("SELF_REPORTED", "SELF_REPORTED"): "UNCHANGED",
}


def _hold(*, invalid: bool) -> dict[str, object]:
    return {
        "status": "HOLD",
        "provenance": "UNVERIFIED",
        "reason_code": ("INVALID_OR_INCOMPLETE_COMPARISON" if invalid else
                        "INDEPENDENT_SOURCE_AND_HUMAN_REVIEW_REQUIRED"),
        "changes": [],
        "new_blockers": [],
        "withdrawn_claims": [],
        "new_unverified_claims": [],
        "unchanged_count": 0,
        "previous_self_reported": 0,
        "current_self_reported": 0,
        **{name: False for name in FLAGS},
    }


def compare(raw: bytes) -> dict[str, object]:
    """Validate both *complete* fixed-shape packets atomically before diffing."""
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise InvalidPacket("invalid comparison size")
    try:
        envelope = json.loads(raw.decode("utf-8", "strict"),
                              object_pairs_hook=_unique_pairs,
                              parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise InvalidPacket("invalid comparison") from exc

    if type(envelope) is not dict or set(envelope) != {"schema", "previous", "current"}:
        raise InvalidPacket("invalid comparison structure")
    if type(envelope["schema"]) is not int or envelope["schema"] != 1:
        raise InvalidPacket("invalid comparison schema")

    # Reuse the single-source strict inventory validator. JSON is re-encoded
    # only after *all* nested duplicate-key checks have already completed.
    validated = []
    for key in ("previous", "current"):
        value = envelope[key]
        if type(value) is not dict:
            raise InvalidPacket("invalid packet type")
        try:
            snapshot = assess(json.dumps(value, allow_nan=False, ensure_ascii=True,
                                         separators=(",", ":")).encode("ascii"))
        except (InvalidPacket, ValueError, TypeError, OverflowError) as exc:
            raise InvalidPacket("invalid packet") from exc
        validated.append(snapshot)

    old, new = validated
    out = _hold(invalid=False)
    out["previous_self_reported"] = old["self_reported_count"]
    out["current_self_reported"] = new["self_reported_count"]
    changes = []
    for gate in GATES:
        before = old["gate_states"][gate]
        after = new["gate_states"][gate]
        label = TRANSITIONS[(before, after)]
        if label != "UNCHANGED":
            changes.append({
                "gate": gate, "previous": before, "current": after,
                "transition": label,
            })
        else:
            out["unchanged_count"] += 1
    out["changes"] = changes
    out["new_blockers"] = [item["gate"] for item in changes if item["transition"]
                           in {"NEW_BLOCKER", "CLAIM_WITHDRAWN_AND_BLOCKED"}]
    out["withdrawn_claims"] = [item["gate"] for item in changes if item["transition"]
                               in {"CLAIM_WITHDRAWN", "CLAIM_WITHDRAWN_AND_BLOCKED"}]
    out["new_unverified_claims"] = [
        item["gate"] for item in changes
        if item["transition"] == "NEW_UNVERIFIED_CLAIM"
    ]
    return out


def main() -> int:
    try:
        result = compare(read_bounded_stdin(MAX_BYTES))
    except (InvalidPacket, OSError):
        result = _hold(invalid=True)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
