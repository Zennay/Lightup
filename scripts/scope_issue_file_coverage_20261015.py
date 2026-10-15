"""Offline LightUp PR-file pagination consistency gate.

An exact-path conflict is only a useful observation if no PR file page was
silently omitted. Completeness is *self-asserted*, never trusted GitHub proof.
"""
from __future__ import annotations

import json
import sys

from scope_issue_ownership_audit_20261015 import (
    MAX_INPUT, MAX_PATHS, InvalidSnapshot, _pairs, _path, _positive_int,
)
from scope_issue_snapshot_coverage_20261015 import witness


FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def file_coverage(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_INPUT:
        raise InvalidSnapshot("invalid file coverage receipt")
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(InvalidSnapshot("nonfinite")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidSnapshot("invalid JSON") from exc
    if type(payload) is not dict or set(payload) != {"snapshot", "pagination", "pr_file_pages"}:
        raise InvalidSnapshot("invalid receipt shape")
    snapshot = payload["snapshot"]
    receipts = payload["pr_file_pages"]
    if type(snapshot) is not dict or type(receipts) is not list or len(receipts) > MAX_PATHS:
        raise InvalidSnapshot("invalid file receipts")
    # The earlier source-coverage witness validates issue/PR shapes and page listings.
    checked = witness(json.dumps({"snapshot": snapshot, "pagination": payload["pagination"]},
                                 ensure_ascii=True).encode("utf-8"))
    open_prs = {p["number"]: p for p in snapshot["prs"] if p["open"] is True}
    covered = set()
    states = {}
    for item in receipts:
        if type(item) is not dict or set(item) != {"pr", "pages"}:
            raise InvalidSnapshot("invalid file page record")
        pr = _positive_int(item["pr"])
        if pr not in open_prs or pr in covered:
            raise InvalidSnapshot("unmatched or duplicate PR files")
        covered.add(pr)
        pages = item["pages"]
        if type(pages) is not list or not pages or len(pages) > MAX_PATHS:
            raise InvalidSnapshot("invalid file page count")
        observed = set()
        last_has_next = None
        for index, page in enumerate(pages, 1):
            if type(page) is not dict or set(page) != {"page", "paths", "has_next"}:
                raise InvalidSnapshot("invalid file page shape")
            if type(page["page"]) is not int or page["page"] != index:
                raise InvalidSnapshot("nonconsecutive file pages")
            if type(page["has_next"]) is not bool:
                raise InvalidSnapshot("invalid file page marker")
            if index < len(pages) and page["has_next"] is not True:
                raise InvalidSnapshot("incoherent intermediate file page")
            entries = page["paths"]
            if type(entries) is not list or len(entries) > 100:
                raise InvalidSnapshot("invalid file paths page")
            paths = [_path(p) for p in entries]
            if len(paths) != len(set(paths)) or observed.intersection(paths):
                raise InvalidSnapshot("duplicate file across pages")
            observed.update(paths)
            last_has_next = page["has_next"]
            if len(observed) > MAX_PATHS:
                raise InvalidSnapshot("excess files")
        if observed != set(open_prs[pr]["paths"]):
            raise InvalidSnapshot("file evidence disagrees with PR snapshot")
        states[pr] = ("INCOMPLETE_MORE_FILE_PAGES" if last_has_next
                      else "SELF_ASSERTED_COMPLETE_UNVERIFIED")

    # Missing open-PR file evidence is not an empty diff. Suppress all apparent
    # free-work hints and any claim of collision-free work, even with clean pages.
    missing = sorted(set(open_prs) - covered)
    for pr in missing:
        states[pr] = "MISSING_PR_FILE_EVIDENCE"
    all_files_self_asserted = not missing and all(
        state == "SELF_ASSERTED_COMPLETE_UNVERIFIED" for state in states.values()
    )
    all_pages_self_asserted = checked["all_pages_self_asserted_complete"]
    complete = all_files_self_asserted and all_pages_self_asserted
    return {
        "status": "HOLD",
        "source_provenance_verified": False,
        "worker_activity_verified": False,
        "can_authorize": False, "can_scan": False, "can_merge": False,
        "can_deploy": False, "can_release": False,
        "issue_pr_page_coverage": checked["pagination"],
        "pr_file_coverage": [{"pr": pr, "coverage": states[pr]} for pr in sorted(states)],
        "all_pages_self_asserted_complete": complete,
        "file_collision_assessment": (
            "OBSERVED_ONLY_UNVERIFIED" if complete else "INCOMPLETE_NOT_EXHAUSTIVE"),
        "candidate_list_suppressed": not complete,
        "unclaimed_candidates_not_permission": (
            checked["unclaimed_candidates_not_permission"] if complete else []),
        # Positive observed conflicts remain review hints; absence of conflicts
        # cannot certify unique file ownership.
        "observed_review_groups": checked["review_groups"],
        "reason": "Caller-controlled offline file paging does not confer worker ownership",
    }


def main() -> int:
    try:
        output = file_coverage(sys.stdin.buffer.read(MAX_INPUT + 1))
    except (InvalidSnapshot, ValueError, TypeError, KeyError, OSError, RecursionError):
        output = {
            "status": "HOLD", "source_provenance_verified": False,
            "worker_activity_verified": False,
            "can_authorize": False, "can_scan": False, "can_merge": False,
            "can_deploy": False, "can_release": False,
            "all_pages_self_asserted_complete": False,
            "file_collision_assessment": "INVALID_OR_UNTRUSTED",
            "candidate_list_suppressed": True,
            "unclaimed_candidates_not_permission": [],
            "observed_review_groups": [],
            "pr_file_coverage": [],
            "reason": "Invalid or untrusted offline file paging receipt",
        }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
