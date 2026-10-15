"""Offline PR/issue conflict components for LightUp's synthetic ownership audit.

Groups are review hints, NEVER permission to take over another worker's branch.
"""
from __future__ import annotations

import json
import sys

from scope_issue_ownership_audit_20261015 import MAX_INPUT, InvalidSnapshot, audit

FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def conflict_groups(result: dict) -> dict:
    """Group transitive exact-path and duplicate-issue collisions in linear time."""
    if (type(result) is not dict or result.get("status") != "HOLD"
            or any(result.get(flag) is not False for flag in FLAGS)):
        raise InvalidSnapshot("invalid audit status")
    duplicates = result["duplicate_issue_claims"]
    paths = result["exact_path_collisions"]
    if type(duplicates) is not list or type(paths) is not list:
        raise InvalidSnapshot("invalid conflicts")

    parents: dict[int, int] = {}

    def find(pr: int) -> int:
        if type(pr) is not int or pr < 1:
            raise InvalidSnapshot("invalid PR identity")
        parents.setdefault(pr, pr)
        while parents[pr] != pr:
            parents[pr] = parents[parents[pr]]
            pr = parents[pr]
        return pr

    def connect(ids: list[int]) -> None:
        if type(ids) is not list or len(ids) < 2:
            raise InvalidSnapshot("invalid conflict edge")
        root = find(ids[0])
        for pr in ids[1:]:
            second = find(pr)
            parents[second] = root

    for row in duplicates:
        if type(row) is not dict or set(row) != {"issue", "prs"} or type(row["issue"]) is not int:
            raise InvalidSnapshot("invalid issue conflict")
        connect(row["prs"])
    for row in paths:
        if type(row) is not dict or set(row) != {"path", "prs"} or type(row["path"]) is not str:
            raise InvalidSnapshot("invalid file conflict")
        connect(row["prs"])

    components: dict[int, list[int]] = {}
    for number in sorted(parents):
        components.setdefault(find(number), []).append(number)

    groups = []
    for members in components.values():
        if len(members) < 2:
            continue
        member_set = set(members)
        issue_ids = sorted(row["issue"] for row in duplicates
                           if member_set.intersection(row["prs"]))
        path_ids = sorted(row["path"] for row in paths
                          if member_set.intersection(row["prs"]))
        groups.append({"prs": sorted(members), "duplicate_issues": issue_ids,
                       "colliding_paths": path_ids, "review_priority":
                       "PATH_AND_ISSUE" if issue_ids and path_ids
                       else "PATH" if path_ids else "ISSUE"})
    groups.sort(key=lambda group: group["prs"][0])
    return {
        "status": "HOLD",
        "source_coverage": "UNVERIFIED_UNTRUSTED_SNAPSHOT",
        "can_authorize": False, "can_scan": False, "can_merge": False,
        "can_deploy": False, "can_release": False,
        "group_count": len(groups), "review_groups": groups,
        "no_conflict_does_not_mean_available": True,
        "unknown_worker_activity": True,
        "unclaimed_candidates_not_permission": result["unclaimed_open_issues"],
    }


def main() -> int:
    try:
        result = conflict_groups(audit(sys.stdin.buffer.read(MAX_INPUT + 1)))
    except (InvalidSnapshot, ValueError, TypeError, KeyError, OSError, RecursionError):
        result = {
            "status": "HOLD", "source_coverage": "INVALID_OR_UNTRUSTED",
            "can_authorize": False, "can_scan": False, "can_merge": False,
            "can_deploy": False, "can_release": False,
            "group_count": 0, "review_groups": [],
            "no_conflict_does_not_mean_available": True,
            "unknown_worker_activity": True,
            "unclaimed_candidates_not_permission": [],
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
