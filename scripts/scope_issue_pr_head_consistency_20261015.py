"""Offline PR head-drift witness for a LightUp scope worker review receipt.

No API calls, Git operations, locks, approvals or active target interactions.
All input including SHA text is self-asserted, not GitHub authenticity proof.
"""
from __future__ import annotations

import json
import re
import sys

from scope_issue_ownership_audit_20261015 import MAX_INPUT, InvalidSnapshot, _pairs, _positive_int
from scope_issue_rename_footprints_20261015 import rename_footprints

SHA_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


def _sha(value: object) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None or set(value) == {"0"}:
        raise InvalidSnapshot("invalid head identifier")
    return value


def head_consistency(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_INPUT:
        raise InvalidSnapshot("invalid head receipt")
    try:
        envelope = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(InvalidSnapshot("nonfinite")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidSnapshot("invalid JSON receipt") from exc
    if type(envelope) is not dict or set(envelope) != {
        "snapshot", "pagination", "pr_file_pages", "pr_change_pages", "pr_head_receipts"
    }:
        raise InvalidSnapshot("invalid envelope")
    base_data = {key: envelope[key] for key in (
        "snapshot", "pagination", "pr_file_pages", "pr_change_pages"
    )}
    base = rename_footprints(json.dumps(base_data, ensure_ascii=True).encode("utf-8"))
    snapshot = envelope["snapshot"]
    open_ids = {item["number"] for item in snapshot["prs"] if item["open"] is True}
    file_receipts = {item["pr"]: item for item in envelope["pr_file_pages"]}
    change_receipts = {item["pr"]: item for item in envelope["pr_change_pages"]}
    receipts = envelope["pr_head_receipts"]
    if type(receipts) is not list or len(receipts) > 4000:
        raise InvalidSnapshot("invalid head receipt collection")

    seen: set[int] = set()
    states: dict[int, str] = {}
    for row in receipts:
        if type(row) is not dict or set(row) != {
            "pr", "start_head", "file_page_heads", "change_page_heads", "end_head"
        }:
            raise InvalidSnapshot("invalid head shape")
        pr = _positive_int(row["pr"])
        if pr not in open_ids or pr in seen:
            raise InvalidSnapshot("unknown or repeated head evidence")
        seen.add(pr)
        first, last = _sha(row["start_head"]), _sha(row["end_head"])
        file_heads, change_heads = row["file_page_heads"], row["change_page_heads"]
        if type(file_heads) is not list or type(change_heads) is not list:
            raise InvalidSnapshot("invalid page head collection")
        if (pr not in file_receipts or pr not in change_receipts
                or len(file_heads) != len(file_receipts[pr]["pages"])
                or len(change_heads) != len(change_receipts[pr]["pages"])):
            states[pr] = "INCOMPLETE_HEAD_PAGE_EVIDENCE"
            continue
        pinned = [_sha(v) for v in file_heads + change_heads]
        states[pr] = (
            "SELF_ASSERTED_STABLE_UNVERIFIED"
            if all(x == first for x in [last, *pinned])
            else "HEAD_CHANGED_OR_MIXED_VERSIONS"
        )
    for missing in open_ids - seen:
        states[missing] = "MISSING_HEAD_EVIDENCE"

    complete = (
        base["file_change_coverage"] == "SELF_ASSERTED_COMPLETE_UNVERIFIED"
        and len(states) == len(open_ids)
        and all(x == "SELF_ASSERTED_STABLE_UNVERIFIED" for x in states.values())
    )
    # Even a self-asserted stable, exhaustive export does not show current live
    # worker ownership. Never emit 'available', 'ready', or permission flags.
    return {
        "status": "HOLD",
        "can_authorize": False, "can_scan": False, "can_merge": False,
        "can_deploy": False, "can_release": False,
        "source_provenance_verified": False,
        "worker_activity_verified": False,
        "pr_head_states": [
            {"pr": pr, "head_state": states[pr]} for pr in sorted(states)
        ],
        "review_consistency": (
            "SELF_ASSERTED_STABLE_UNVERIFIED" if complete else "UNSTABLE_OR_INCOMPLETE"
        ),
        "candidate_list_suppressed": True,
        "unclaimed_candidates_not_permission": [],
        "observed_conflict_groups": (
            base["observed_conflict_groups"] if complete else []
        ),
        "conflicts_suppressed_for_mixed_heads": not complete,
        "reason": "Caller-supplied PR SHA observations cannot prove GitHub provenance, freshness or worker ownership",
    }


def main() -> int:
    try:
        result = head_consistency(sys.stdin.buffer.read(MAX_INPUT + 1))
    except (InvalidSnapshot, ValueError, KeyError, TypeError, OSError, RecursionError):
        result = {
            "status": "HOLD", "can_authorize": False, "can_scan": False,
            "can_merge": False, "can_deploy": False, "can_release": False,
            "source_provenance_verified": False, "worker_activity_verified": False,
            "pr_head_states": [], "review_consistency": "INVALID_OR_UNTRUSTED",
            "candidate_list_suppressed": True, "unclaimed_candidates_not_permission": [],
            "observed_conflict_groups": [], "conflicts_suppressed_for_mixed_heads": True,
            "reason": "Invalid untrusted head observations",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
