"""Read-only, offline GitHub rename footprints for LightUp scope worker PRs.

GitHub's PR-file endpoint reports the *new* filename for renames. Treating
that alone as the touched resource can hide conflicts on previous_filename.
The caller supplies an untrusted paging receipt; never grant work ownership.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict

from scope_issue_ownership_audit_20261015 import MAX_INPUT, MAX_PATHS, InvalidSnapshot, _pairs, _path, _positive_int, audit
from scope_issue_file_coverage_20261015 import file_coverage
from scope_issue_ownership_clusters_20261015 import conflict_groups


def rename_footprints(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_INPUT:
        raise InvalidSnapshot("invalid receipt length")
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(InvalidSnapshot("nonfinite")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InvalidSnapshot("malformed JSON") from exc
    if type(payload) is not dict or set(payload) != {"snapshot", "pagination", "pr_file_pages", "pr_change_pages"}:
        raise InvalidSnapshot("invalid receipt shape")
    base = file_coverage(json.dumps({
        "snapshot": payload["snapshot"], "pagination": payload["pagination"],
        "pr_file_pages": payload["pr_file_pages"]}, ensure_ascii=True).encode())
    changes = payload["pr_change_pages"]
    if type(changes) is not list or len(changes) > MAX_PATHS:
        raise InvalidSnapshot("invalid change page collection")
    prs = {p["number"]: p for p in payload["snapshot"]["prs"] if p["open"]}
    seen_prs = set()
    touched = defaultdict(set)
    incomplete = False
    for record in changes:
        if type(record) is not dict or set(record) != {"pr", "pages"}:
            raise InvalidSnapshot("invalid changed PR receipt")
        pr = _positive_int(record["pr"])
        if pr not in prs or pr in seen_prs:
            raise InvalidSnapshot("unmatched or duplicate changed PR")
        seen_prs.add(pr)
        pages = record["pages"]
        if type(pages) is not list or not pages or len(pages) > MAX_PATHS:
            raise InvalidSnapshot("invalid changed pages")
        new_paths = set()
        for number, page in enumerate(pages, 1):
            if type(page) is not dict or set(page) != {"page", "has_next", "changes"}:
                raise InvalidSnapshot("invalid changed page shape")
            if type(page["page"]) is not int or page["page"] != number:
                raise InvalidSnapshot("nonconsecutive changed pages")
            if type(page["has_next"]) is not bool:
                raise InvalidSnapshot("bad has_next")
            if number < len(pages) and page["has_next"] is not True:
                raise InvalidSnapshot("early changed pagination end")
            entries = page["changes"]
            if type(entries) is not list or len(entries) > 100:
                raise InvalidSnapshot("invalid file change page size")
            for entry in entries:
                if type(entry) is not dict or set(entry) != {"filename", "status", "previous_filename"}:
                    raise InvalidSnapshot("invalid file change shape")
                path = _path(entry["filename"])
                state = entry["status"]
                if type(state) is not str or state not in ("added", "modified", "removed", "renamed", "copied", "changed", "unchanged"):
                    raise InvalidSnapshot("unsupported file change status")
                old = entry["previous_filename"]
                if state == "renamed":
                    if type(old) is not str:
                        raise InvalidSnapshot("renamed file missing previous identity")
                    old = _path(old)
                    if old == path:
                        raise InvalidSnapshot("non-changing rename")
                elif old is not None:
                    raise InvalidSnapshot("previous identity only valid for renames")
                if path in new_paths:
                    raise InvalidSnapshot("duplicate PR new path")
                new_paths.add(path)
                touched[path].add(pr)
                if old is not None:
                    touched[old].add(pr)
                if len(new_paths) > MAX_PATHS or len(touched) > MAX_PATHS * 2:
                    raise InvalidSnapshot("too many changed paths")
        if new_paths != set(prs[pr]["paths"]):
            raise InvalidSnapshot("changed paths differ from snapshot")
        if pages[-1]["has_next"]:
            incomplete = True
    if set(prs) - seen_prs:
        incomplete = True
    effective_collisions = [
        {"path": path, "prs": sorted(owners)}
        for path, owners in sorted(touched.items()) if len(owners) > 1
    ]
    initial = audit(json.dumps(payload["snapshot"], ensure_ascii=True).encode())
    initial["exact_path_collisions"] = effective_collisions
    groups = conflict_groups(initial)
    complete = base["all_pages_self_asserted_complete"] and not incomplete
    return {
        "status": "HOLD",
        "can_authorize": False, "can_scan": False, "can_merge": False,
        "can_deploy": False, "can_release": False,
        "source_provenance_verified": False,
        "worker_activity_verified": False,
        "file_change_coverage": "SELF_ASSERTED_COMPLETE_UNVERIFIED" if complete else "INCOMPLETE_NOT_EXHAUSTIVE",
        "candidate_list_suppressed": True,
        "unclaimed_candidates_not_permission": [],
        "observed_path_collisions": effective_collisions,
        "observed_conflict_groups": groups["review_groups"],
        "no_conflicts_does_not_mean_free": True,
        "reason": "Untrusted offline rename/path observations; no authority to assign work",
    }


def main() -> int:
    try:
        result = rename_footprints(sys.stdin.buffer.read(MAX_INPUT + 1))
    except (InvalidSnapshot, ValueError, KeyError, TypeError, OSError, RecursionError):
        result = {
            "status": "HOLD",
            "can_authorize": False, "can_scan": False, "can_merge": False,
            "can_deploy": False, "can_release": False,
            "source_provenance_verified": False, "worker_activity_verified": False,
            "file_change_coverage": "INVALID_OR_UNTRUSTED",
            "candidate_list_suppressed": True,
            "unclaimed_candidates_not_permission": [],
            "observed_path_collisions": [], "observed_conflict_groups": [],
            "no_conflicts_does_not_mean_free": True,
            "reason": "Invalid or untrusted offline file change receipt",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
