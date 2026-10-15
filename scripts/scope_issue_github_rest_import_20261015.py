"""Offline adapter for *actual GitHub REST record shapes*, never an owner grant.

Input is a user-supplied, untrusted collection of GitHub issues/pulls/files
response pages. No network/API access. GitHub issues don't have Notion lanes,
so the caller must separately supply scope issue numbers and explicit PR claims.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict

from scope_issue_ownership_audit_20261015 import (
    InvalidSnapshot, MAX_INPUT, MAX_PATHS, MAX_ROWS, _pairs, _positive_int, _path, audit
)
from scope_issue_ownership_clusters_20261015 import conflict_groups

REPO = "Zennay/Lightup"
FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def _pages(value, label):
    if type(value) is not list or not value or len(value) > MAX_ROWS:
        raise InvalidSnapshot("missing or oversized " + label)
    seen = []
    for i, page in enumerate(value, 1):
        if type(page) is not dict or set(page) != {"page", "has_next", "records"}:
            raise InvalidSnapshot("invalid " + label + " page")
        if type(page["page"]) is not int or page["page"] != i:
            raise InvalidSnapshot("nonconsecutive " + label)
        if type(page["has_next"]) is not bool:
            raise InvalidSnapshot("invalid next marker")
        if i < len(value) and page["has_next"] is not True:
            raise InvalidSnapshot("premature page ending")
        rows = page["records"]
        if type(rows) is not list or len(rows) > 100:
            raise InvalidSnapshot("invalid page rows")
        seen.extend(rows)
    return seen, not value[-1]["has_next"]


def _repo(ref):
    if type(ref) is not dict or type(ref.get("full_name")) is not str:
        raise InvalidSnapshot("missing repository identity")
    return ref["full_name"]


def _sha(value):
    if type(value) is not str or len(value) not in (40, 64):
        raise InvalidSnapshot("invalid SHA")
    if any(ch not in "0123456789abcdef" for ch in value) or set(value) == {"0"}:
        raise InvalidSnapshot("invalid SHA")
    return value


def review(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_INPUT:
        raise InvalidSnapshot("invalid import size")
    try:
        data = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InvalidSnapshot("nonfinite")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidSnapshot("invalid import JSON") from exc
    if type(data) is not dict or set(data) != {
        "repository", "issue_pages", "pr_pages", "file_pages",
        "scope_issue_numbers", "claims"
    } or data["repository"] != REPO:
        raise InvalidSnapshot("invalid import envelope")
    issue_rows, issues_complete = _pages(data["issue_pages"], "issue")
    pr_rows, prs_complete = _pages(data["pr_pages"], "PR")
    raw_issues = {}
    for row in issue_rows:
        if type(row) is not dict or row.get("pull_request") is not None:
            raise InvalidSnapshot("PR mistakenly included among issue rows")
        number = _positive_int(row.get("number"))
        if number in raw_issues or row.get("state") not in ("open", "closed"):
            raise InvalidSnapshot("duplicate/invalid issue")
        raw_issues[number] = row
    scope = data["scope_issue_numbers"]
    if type(scope) is not list or len(scope) > MAX_ROWS:
        raise InvalidSnapshot("invalid Notion scope issue selection")
    scope_ids = [_positive_int(number) for number in scope]
    if len(set(scope_ids)) != len(scope_ids) or not set(scope_ids).issubset(raw_issues):
        raise InvalidSnapshot("missing selected scope issue")
    issues = [{"number": n, "open": raw_issues[n]["state"] == "open",
               "lane": "scope-authorization"} for n in sorted(scope_ids)]

    prs = {}
    for row in pr_rows:
        if type(row) is not dict:
            raise InvalidSnapshot("invalid PR row")
        number = _positive_int(row.get("number"))
        if number in prs or row.get("state") not in ("open", "closed") or type(row.get("draft")) is not bool:
            raise InvalidSnapshot("duplicate/invalid PR")
        base, head = row.get("base"), row.get("head")
        if type(base) is not dict or type(head) is not dict:
            raise InvalidSnapshot("missing PR branches")
        if _repo(base.get("repo")) != REPO or base.get("ref") != "main":
            raise InvalidSnapshot("wrong base repository")
        _sha(base.get("sha")); _sha(head.get("sha"))
        head_repo = _repo(head.get("repo"))
        # Forks are legitimate, but never implicit owner claims.
        prs[number] = {"number": number, "open": row["state"] == "open",
                       "draft": row["draft"], "issues": [], "paths": [],
                       "fork": head_repo != REPO}

    claim_rows = data["claims"]
    if type(claim_rows) is not list or len(claim_rows) > MAX_ROWS:
        raise InvalidSnapshot("invalid explicit owner claims")
    claimed = set()
    for item in claim_rows:
        if type(item) is not dict or set(item) != {"pr", "issues"}:
            raise InvalidSnapshot("invalid claim")
        pr = _positive_int(item["pr"])
        if pr not in prs or pr in claimed or type(item["issues"]) is not list:
            raise InvalidSnapshot("duplicate or foreign claim")
        claimed.add(pr)
        values = [_positive_int(i) for i in item["issues"]]
        if len(values) != len(set(values)) or len(values) > MAX_ROWS:
            raise InvalidSnapshot("duplicate claim issue")
        prs[pr]["issues"] = values

    file_receipts = data["file_pages"]
    if type(file_receipts) is not list or len(file_receipts) > MAX_PATHS:
        raise InvalidSnapshot("invalid file pages")
    by_pr = defaultdict(list)
    for page in file_receipts:
        if type(page) is not dict or set(page) != {"pr", "page", "has_next", "records"}:
            raise InvalidSnapshot("invalid file page")
        pr = _positive_int(page["pr"])
        if pr not in prs or not prs[pr]["open"]:
            raise InvalidSnapshot("file pages for unknown/closed PR")
        by_pr[pr].append({k: page[k] for k in ("page", "has_next", "records")})

    footprints = defaultdict(set)
    complete_files = True
    total_files = 0
    for pr, item in sorted(prs.items()):
        if not item["open"]:
            continue
        if pr not in by_pr:
            complete_files = False
            continue
        records, complete = _pages(by_pr[pr], "PR file")
        complete_files = complete_files and complete
        seen_paths = set()
        for file in records:
            if type(file) is not dict:
                raise InvalidSnapshot("invalid PR file")
            name = _path(file.get("filename"))
            status = file.get("status")
            if status not in ("added", "modified", "removed", "renamed", "copied", "changed", "unchanged"):
                raise InvalidSnapshot("unknown file status")
            previous = file.get("previous_filename")
            if status == "renamed":
                previous = _path(previous)
                if previous == name:
                    raise InvalidSnapshot("invalid rename")
            elif previous is not None:
                raise InvalidSnapshot("unexpected original filename")
            if name in seen_paths:
                raise InvalidSnapshot("duplicate changed path")
            seen_paths.add(name)
            footprints[name].add(pr)
            if previous is not None:
                footprints[previous].add(pr)
            total_files += 1
            if total_files > MAX_PATHS:
                raise InvalidSnapshot("too many changed paths")
        item["paths"] = sorted(seen_paths)

    normalized = {"issues": issues, "prs": [
        {key: value for key, value in p.items() if key != "fork"}
        for _, p in sorted(prs.items())
    ]}
    base = audit(json.dumps(normalized, ensure_ascii=True).encode("utf-8"))
    path_collisions = [{"path": name, "prs": sorted(values)}
                       for name, values in sorted(footprints.items()) if len(values) > 1]
    base["exact_path_collisions"] = path_collisions
    grouped = conflict_groups(base)
    complete = issues_complete and prs_complete and complete_files and (
        all(n in by_pr for n, p in prs.items() if p["open"])
    ) and all(n in claimed for n, p in prs.items() if p["open"])
    return {
        "status": "HOLD",
        "can_authorize": False, "can_scan": False, "can_merge": False,
        "can_deploy": False, "can_release": False,
        "source_provenance_verified": False, "worker_activity_verified": False,
        "snapshot_complete_self_asserted": complete,
        "head_pinning_verified": False,
        "conflict_observations": grouped["review_groups"],
        "observed_path_collisions": path_collisions,
        "open_fork_prs_require_review": sorted(n for n, p in prs.items() if p["open"] and p["fork"]),
        "missing_claim_declarations": sorted(n for n, p in prs.items() if p["open"] and n not in claimed),
        "candidate_list_suppressed": True,
        "unclaimed_candidates_not_permission": [],
        "reason": "GitHub REST record-shaped offline import is untrusted, unpinned and never work authority",
    }


def main() -> int:
    try:
        result = review(sys.stdin.buffer.read(MAX_INPUT + 1))
    except (InvalidSnapshot, ValueError, TypeError, KeyError, OSError, RecursionError):
        result = {
            "status": "HOLD", "can_authorize": False, "can_scan": False,
            "can_merge": False, "can_deploy": False, "can_release": False,
            "source_provenance_verified": False, "worker_activity_verified": False,
            "snapshot_complete_self_asserted": False, "head_pinning_verified": False,
            "conflict_observations": [], "observed_path_collisions": [],
            "open_fork_prs_require_review": [], "missing_claim_declarations": [],
            "candidate_list_suppressed": True, "unclaimed_candidates_not_permission": [],
            "reason": "Invalid offline GitHub export",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
