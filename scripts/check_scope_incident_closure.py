"""Offline incident closure evidence checker. Never grants execution authority.

Only validates a local JSON record; no network, DB or target interaction.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

REQUIRED = frozenset({
    "incident_id", "observed_at_utc", "tenant_id", "engagement_id", "run_id",
    "grant_id", "expected_version", "observed_version",
    "revoked_or_narrowed_dimensions", "queued_child_ids", "inflight_child_ids",
    "stop_requested_at", "stop_acknowledged_at", "terminal_state_by_child",
    "audit_receipt_refs", "reviewer_id", "review_at_utc", "closure_decision",
})
TERMINAL = frozenset({"cancelled", "completed", "failed"})


def closure_is_proven(record: object) -> bool:
    """Return False on missing, ambiguous or unexpectedly typed evidence."""
    if type(record) is not dict or set(record) != REQUIRED:
        return False
    for key in REQUIRED - {"queued_child_ids", "inflight_child_ids",
                           "terminal_state_by_child", "audit_receipt_refs",
                           "revoked_or_narrowed_dimensions"}:
        if type(record[key]) is not str or not record[key].strip():
            return False
    if record["closure_decision"] != "approved_closed":
        return False
    for key in ("queued_child_ids", "inflight_child_ids", "audit_receipt_refs",
                "revoked_or_narrowed_dimensions"):
        if type(record[key]) is not list:
            return False
        if any(type(x) is not str or not x.strip() for x in record[key]):
            return False
        if len(record[key]) != len(set(record[key])):
            return False
    if not record["audit_receipt_refs"] or not record["revoked_or_narrowed_dimensions"]:
        return False
    child_ids = record["queued_child_ids"] + record["inflight_child_ids"]
    if len(child_ids) != len(set(child_ids)):
        return False
    states = record["terminal_state_by_child"]
    if type(states) is not dict or set(states) != set(child_ids):
        return False
    if any(type(v) is not str or v not in TERMINAL for v in states.values()):
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: check_scope_incident_closure.py <local-json-file>", file=sys.stderr)
        return 2
    try:
        record = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        print("NOT PROVEN", file=sys.stderr)
        return 1
    if not closure_is_proven(record):
        print("NOT PROVEN", file=sys.stderr)
        return 1
    print("STRUCTURE VALID ONLY — independent evidence review still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
