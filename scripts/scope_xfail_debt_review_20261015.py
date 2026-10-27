"""Offline, non-authorizing review of explicitly expected authorization test failures.

Consumes a caller-provided synthetic JSON snapshot on stdin. No GitHub, filesystem
inventory, target, DNS, sockets, grants or production integration. ALWAYS HOLD.
"""
from __future__ import annotations

import json
import sys

MAX_BYTES = 65536
MAX_CASES = 512
OUTCOMES = frozenset(("passed", "expected_failure", "unexpected_success",
                     "failed", "error", "skipped"))
RECEIPT_FALSE = ("authorization_verified", "permit_issued",
                 "execution_enabled", "merge_approved", "release_approved",
                 "scan_allowed")


class SnapshotError(ValueError):
    pass


def _reject_constant(_value: str):
    raise SnapshotError("invalid constant")


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise SnapshotError("duplicate key")
        obj[key] = value
    return obj


def _integer(value):
    return type(value) is int and 0 < value <= 10000000


def _case_id(value):
    return (type(value) is str and 1 <= len(value) <= 128
            and all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_." for c in value)
            and value[0].isalpha())


def _validate(snapshot):
    if type(snapshot) is not dict or set(snapshot) != {"schema_version", "complete", "cases"}:
        raise SnapshotError("shape")
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
        raise SnapshotError("version")
    if type(snapshot["complete"]) is not bool:
        raise SnapshotError("completeness")
    cases = snapshot["cases"]
    if type(cases) is not list or not (1 <= len(cases) <= MAX_CASES):
        raise SnapshotError("cases")
    seen = set()
    counts = dict.fromkeys(OUTCOMES, 0)
    unowned = set()
    issues = set()
    for entry in cases:
        if type(entry) is not dict or set(entry) != {"issue", "test", "outcome", "owner_pr"}:
            raise SnapshotError("entry")
        issue, name = entry["issue"], entry["test"]
        owner, outcome = entry["owner_pr"], entry["outcome"]
        if not _integer(issue) or not _case_id(name):
            raise SnapshotError("identity")
        if owner is not None and not _integer(owner):
            raise SnapshotError("owner")
        if type(outcome) is not str or outcome not in OUTCOMES:
            raise SnapshotError("outcome")
        identity = (issue, name)
        if identity in seen:
            raise SnapshotError("duplicate test")
        seen.add(identity)
        issues.add(issue)
        counts[outcome] += 1
        if owner is None:
            unowned.add(issue)
    return {
        "expected_red": counts["expected_failure"],
        "unexpected_success": counts["unexpected_success"],
        "other_nonpassing": sum(counts[k] for k in ("failed", "error", "skipped")),
        "ordinary_pass": counts["passed"],
        "unowned_issues": len(unowned),
        "issues": len(issues),
        "cases": len(cases),
        # This is ALWAYS self-reported. A boolean claiming completeness is not proof.
        "coverage": "SELF_ASSERTED_UNVERIFIED" if snapshot["complete"] else "INCOMPLETE",
    }


def review(raw: bytes):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise SnapshotError("input size")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=_reject_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise SnapshotError("invalid input") from exc
    return _validate(value)


def receipt(summary=None):
    result = {"status": "HOLD", "source": "UNVERIFIED_OFFLINE_SNAPSHOT",
              "release_evidence": False}
    result.update({key: False for key in RECEIPT_FALSE})
    if summary is None:
        result["classification"] = "INVALID_OR_UNVERIFIED"
    else:
        result["classification"] = ("SOURCE_RED_OR_FAILURES_PRESENT"
                                    if (summary["expected_red"] or summary["unexpected_success"]
                                        or summary["other_nonpassing"])
                                    else "NO_RED_REPORTED_NOT_AUTHORITY")
        result["summary"] = summary
    return result


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        output = receipt(review(raw))
    except (SnapshotError, OSError, OverflowError, MemoryError):
        output = receipt()
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
    return 2  # NEVER a successful release/authorization command


if __name__ == "__main__":
    raise SystemExit(main())
