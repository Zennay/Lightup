"""Offline comparison of two self-reported expected-RED debt snapshots.

No source files, external APIs, network, grants or targets; always HOLD/exit 2.
Neither the baseline nor current snapshot has authenticated provenance.
"""
from __future__ import annotations

import json
import sys

from scope_xfail_debt_review_20261015 import (
    MAX_BYTES, RECEIPT_FALSE, SnapshotError, _reject_constant, _unique_pairs,
    _validate,
)


def compare(raw):
    if type(raw) is not bytes or not (0 < len(raw) <= MAX_BYTES):
        raise SnapshotError("size")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                         parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError, TypeError) as exc:
        raise SnapshotError("invalid") from exc
    if (type(obj) is not dict or set(obj) != {"schema_version", "baseline", "current"}
            or type(obj["schema_version"]) is not int or obj["schema_version"] != 1):
        raise SnapshotError("envelope")
    base, current = obj["baseline"], obj["current"]
    _validate(base)
    _validate(current)
    before = {(r["issue"], r["test"]): r for r in base["cases"]}
    after = {(r["issue"], r["test"]): r for r in current["cases"]}
    shared = before.keys() & after.keys()
    count = lambda predicate: sum(1 for key in shared if predicate(before[key], after[key]))
    missing = before.keys() - after.keys()
    added = after.keys() - before.keys()
    return {
        "missing_tests": len(missing),
        "new_tests": len(added),
        "red_still_red": count(lambda a, b: a["outcome"] == b["outcome"] == "expected_failure"),
        "red_to_pass_review_required": count(
            lambda a, b: a["outcome"] == "expected_failure" and b["outcome"] == "passed"),
        "passed_to_red": count(
            lambda a, b: a["outcome"] == "passed" and b["outcome"] == "expected_failure"),
        "unexpected_success_current": sum(
            row["outcome"] == "unexpected_success" for row in after.values()),
        "ownership_changed": count(lambda a, b: a["owner_pr"] != b["owner_pr"]),
        "coverage": "SELF_ASSERTED_UNVERIFIED" if base["complete"] and current["complete"]
                    else "INCOMPLETE",
        "baseline_cases": len(before),
        "current_cases": len(after),
    }


def receipt(diff=None):
    data = {"status": "HOLD", "classification": "UNVERIFIED_TRANSITION",
            "source": "UNVERIFIED_OFFLINE_SNAPSHOTS", "release_evidence": False}
    data.update({name: False for name in RECEIPT_FALSE})
    if diff is not None:
        data["summary"] = diff
    return data


def main():
    try:
        data = receipt(compare(sys.stdin.buffer.read(MAX_BYTES + 1)))
    except (SnapshotError, OSError, OverflowError, MemoryError):
        data = receipt()
    sys.stdout.write(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
