"""Offline repository/base identity fence for LightUp worker conflict receipts.

Prevents accidental mixing of issue/PR numbers from unrelated repositories
or base histories. It does not authenticate GitHub data or authorize work.
"""
from __future__ import annotations

import json
import sys

from scope_issue_ownership_audit_20261015 import MAX_INPUT, InvalidSnapshot, _pairs, _positive_int
from scope_issue_pr_head_consistency_20261015 import _sha, head_consistency

EXPECTED_REPO = "Zennay/Lightup"
EXPECTED_BASE = "main"
FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def repo_identity_fence(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_INPUT:
        raise InvalidSnapshot("oversized or invalid identity receipt")
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(InvalidSnapshot("nonfinite")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidSnapshot("invalid JSON") from exc
    keys = {
        "snapshot", "pagination", "pr_file_pages", "pr_change_pages",
        "pr_head_receipts", "repository", "pr_repository_observations",
    }
    if type(payload) is not dict or set(payload) != keys:
        raise InvalidSnapshot("invalid identity envelope")
    repository = payload["repository"]
    if type(repository) is not dict or set(repository) != {
        "repo", "base_ref", "base_sha"
    }:
        raise InvalidSnapshot("invalid repository identity")
    if repository["repo"] != EXPECTED_REPO or repository["base_ref"] != EXPECTED_BASE:
        raise InvalidSnapshot("unexpected repository/ref")
    base_sha = _sha(repository["base_sha"])

    checked = head_consistency(json.dumps({
        key: payload[key] for key in (
            "snapshot", "pagination", "pr_file_pages", "pr_change_pages",
            "pr_head_receipts"
        )
    }, ensure_ascii=True).encode())
    observations = payload["pr_repository_observations"]
    if type(observations) is not list or len(observations) > 4000:
        raise InvalidSnapshot("invalid repo observation collection")
    open_prs = {p["number"] for p in payload["snapshot"]["prs"] if p["open"] is True}
    known_heads = {x["pr"]: x["end_head"] for x in payload["pr_head_receipts"]}
    statuses: dict[int, str] = {}
    for row in observations:
        if type(row) is not dict or set(row) != {
            "pr", "base_repo", "base_ref", "base_sha",
            "head_repo", "head_sha"
        }:
            raise InvalidSnapshot("invalid PR repo observation shape")
        pr = _positive_int(row["pr"])
        if pr not in open_prs or pr in statuses:
            raise InvalidSnapshot("unknown or duplicate repo observation")
        observed_base = _sha(row["base_sha"])
        observed_head = _sha(row["head_sha"])
        if type(row["base_repo"]) is not str or type(row["base_ref"]) is not str or type(row["head_repo"]) is not str:
            raise InvalidSnapshot("invalid repository label")
        if row["base_repo"] != EXPECTED_REPO or row["base_ref"] != EXPECTED_BASE:
            state = "WRONG_BASE_REPOSITORY_OR_REF"
        elif observed_base != base_sha:
            state = "MIXED_BASE_HISTORY"
        elif row["head_repo"] != EXPECTED_REPO:
            # A fork PR may be legitimate. It is simply NOT ours to claim.
            state = "EXTERNAL_SOURCE_REQUIRES_OWNER_REVIEW"
        elif pr not in known_heads or observed_head != known_heads[pr]:
            state = "HEAD_RECEIPT_MISMATCH"
        else:
            state = "SELF_ASSERTED_REPO_MATCH_UNVERIFIED"
        statuses[pr] = state
    for missing in open_prs - set(statuses):
        statuses[missing] = "MISSING_REPOSITORY_EVIDENCE"

    complete = (
        checked["review_consistency"] == "SELF_ASSERTED_STABLE_UNVERIFIED"
        and all(state == "SELF_ASSERTED_REPO_MATCH_UNVERIFIED"
                for state in statuses.values())
    )
    return {
        "status": "HOLD",
        "can_authorize": False, "can_scan": False, "can_merge": False,
        "can_deploy": False, "can_release": False,
        "source_provenance_verified": False, "worker_activity_verified": False,
        "repository_consistency": (
            "SELF_ASSERTED_MATCH_UNVERIFIED" if complete else "MIXED_OR_INCOMPLETE"
        ),
        "pr_repository_states": [{"pr": n, "state": statuses[n]} for n in sorted(statuses)],
        "review_groups": checked["observed_conflict_groups"] if complete else [],
        "conflicts_suppressed": not complete,
        "candidate_list_suppressed": True,
        "unclaimed_candidates_not_permission": [],
        "reason": "Repo/ref/head receipts are caller-supplied, not authenticated GitHub evidence",
    }


def main() -> int:
    try:
        result = repo_identity_fence(sys.stdin.buffer.read(MAX_INPUT + 1))
    except (InvalidSnapshot, ValueError, KeyError, TypeError, OSError, RecursionError):
        result = {
            "status": "HOLD", "can_authorize": False, "can_scan": False,
            "can_merge": False, "can_deploy": False, "can_release": False,
            "source_provenance_verified": False, "worker_activity_verified": False,
            "repository_consistency": "INVALID_OR_UNTRUSTED",
            "pr_repository_states": [], "review_groups": [],
            "conflicts_suppressed": True, "candidate_list_suppressed": True,
            "unclaimed_candidates_not_permission": [],
            "reason": "Invalid offline repository identity receipt",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
