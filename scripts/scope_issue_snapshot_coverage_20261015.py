"""Fail-closed pagination coverage witness for the offline LightUp ownership audit.

Even consistent pages are self-asserted/untrusted; output cannot imply free work
or target-execution authority. No GitHub API or network access is performed.
"""
from __future__ import annotations

import json
import sys

from scope_issue_ownership_audit_20261015 import (
    MAX_INPUT, MAX_ROWS, InvalidSnapshot, _pairs, _positive_int, audit,
)
from scope_issue_ownership_clusters_20261015 import conflict_groups

FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def _paging(pages: object, expected: set[int]) -> str:
    if type(pages) is not list or not pages or len(pages) > MAX_ROWS:
        raise InvalidSnapshot("missing page coverage")
    seen: set[int] = set()
    for i, page in enumerate(pages, 1):
        if type(page) is not dict or set(page) != {"page", "numbers", "has_next"}:
            raise InvalidSnapshot("invalid page")
        if type(page["page"]) is not int or page["page"] != i:
            raise InvalidSnapshot("nonconsecutive pages")
        if type(page["has_next"]) is not bool:
            raise InvalidSnapshot("invalid next-page marker")
        if type(page["numbers"]) is not list or len(page["numbers"]) > 100:
            raise InvalidSnapshot("invalid page size")
        if i != len(pages) and page["has_next"] is not True:
            raise InvalidSnapshot("premature end marker")
        values = [_positive_int(n) for n in page["numbers"]]
        if len(set(values)) != len(values) or seen.intersection(values):
            raise InvalidSnapshot("duplicated page identity")
        seen.update(values)
    if seen != expected:
        raise InvalidSnapshot("pagination contents mismatch")
    return ("SELF_ASSERTED_COMPLETE_UNVERIFIED" if pages[-1]["has_next"] is False
            else "INCOMPLETE_MORE_PAGES")


def witness(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_INPUT:
        raise InvalidSnapshot("oversized receipt")
    try:
        data = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InvalidSnapshot("nonfinite")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InvalidSnapshot("invalid receipt") from exc
    if type(data) is not dict or set(data) != {"snapshot", "pagination"}:
        raise InvalidSnapshot("invalid receipt shape")
    snap, coverage = data["snapshot"], data["pagination"]
    if type(snap) is not dict or type(coverage) is not dict or set(coverage) != {"issues", "prs"}:
        raise InvalidSnapshot("invalid receipt")
    base = audit(json.dumps(snap, ensure_ascii=True).encode("utf-8"))
    groups = conflict_groups(base)
    # Audit has already validated unique numeric identifiers and exact fields.
    issue_numbers = {x["number"] for x in snap["issues"]}
    pr_numbers = {x["number"] for x in snap["prs"]}
    issue_state = _paging(coverage["issues"], issue_numbers)
    pr_state = _paging(coverage["prs"], pr_numbers)
    complete = issue_state == pr_state == "SELF_ASSERTED_COMPLETE_UNVERIFIED"
    return {
        "status": "HOLD",
        "can_authorize": False, "can_scan": False, "can_merge": False,
        "can_deploy": False, "can_release": False,
        "pagination": {"issues": issue_state, "prs": pr_state},
        "source_provenance_verified": False,
        "all_pages_self_asserted_complete": complete,
        "worker_activity_verified": False,
        "unclaimed_candidates_not_permission": (
            base["unclaimed_open_issues"] if complete else []),
        "candidate_list_suppressed": not complete,
        "review_groups": groups["review_groups"],
        "group_count": groups["group_count"],
        "reason": "Untrusted offline export: page coverage cannot establish human ownership or release",
    }


def main() -> int:
    try:
        result = witness(sys.stdin.buffer.read(MAX_INPUT + 1))
    except (InvalidSnapshot, ValueError, KeyError, OSError, TypeError, RecursionError):
        result = {
            "status": "HOLD", "can_authorize": False, "can_scan": False,
            "can_merge": False, "can_deploy": False, "can_release": False,
            "pagination": {"issues": "UNKNOWN", "prs": "UNKNOWN"},
            "source_provenance_verified": False,
            "all_pages_self_asserted_complete": False,
            "worker_activity_verified": False,
            "unclaimed_candidates_not_permission": [],
            "candidate_list_suppressed": True,
            "review_groups": [], "group_count": 0,
            "reason": "Invalid or incomplete untrusted offline receipt",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
