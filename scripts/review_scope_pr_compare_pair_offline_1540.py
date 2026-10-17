"""Scope #1540: strictly offline PR metadata vs compare-summary consistency.

Two caller-supplied representations are checked against each other before the
unwired, synthetic-only path overlap preview. Neither is authenticated here.
This tool NEVER talks to GitHub, changes a branch, issues consent, or releases.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

_SIBLING = Path(__file__).resolve().with_name(
    "review_scope_compare_snapshots_offline_1540.py")
_spec = importlib.util.spec_from_file_location("scope1540_compare_adapter", _SIBLING)
adapter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adapter)
review = adapter.review

_ROOT = {"version", "base_sha", "reviews"}
_ENTRY = {"worker", "branch", "pr", "compare"}
_PR = {"number", "state", "draft", "base_sha", "head_sha",
       "head_ref", "changed_files"}
_COMPARE = {"base_sha", "head_sha", "status", "ahead_by",
            "behind_by", "too_large", "files"}


def _prepare(raw: bytes) -> bytes:
    payload = review._canonical_decode(raw)
    if type(payload) is not dict or set(payload) != _ROOT:
        raise review.InvalidProposal("root schema")
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise review.InvalidProposal("protocol version")
    pin = payload["base_sha"]
    if not adapter._sha(pin):
        raise review.InvalidProposal("common parent")
    items = payload["reviews"]
    if type(items) is not list or not 2 <= len(items) <= 32:
        raise review.InvalidProposal("review count")

    seen_pr_numbers = set()
    snapshots = []
    for entry in items:
        if type(entry) is not dict or set(entry) != _ENTRY:
            raise review.InvalidProposal("entry fields")
        pr, comp = entry["pr"], entry["compare"]
        if type(pr) is not dict or set(pr) != _PR:
            raise review.InvalidProposal("PR fields")
        if type(comp) is not dict or set(comp) != _COMPARE:
            raise review.InvalidProposal("compare fields")
        number = pr["number"]
        if type(number) is not int or not 1 <= number <= 99_999_999:
            raise review.InvalidProposal("PR number")
        if number in seen_pr_numbers:
            raise review.InvalidProposal("repeated PR number")
        seen_pr_numbers.add(number)
        if pr["state"] != "open" or type(pr["state"]) is not str or pr["draft"] is not True:
            raise review.InvalidProposal("PR status must remain draft")
        if (not adapter._sha(pr["base_sha"])
                or not adapter._sha(pr["head_sha"])
                or pr["base_sha"] != pin
                or pr["head_sha"] == pin):
            raise review.InvalidProposal("PR refs")
        branch = entry["branch"]
        if (type(branch) is not str or type(pr["head_ref"]) is not str
                or not review._safe_branch(branch) or pr["head_ref"] != branch):
            raise review.InvalidProposal("PR branch binding")
        if (not adapter._sha(comp["base_sha"])
                or not adapter._sha(comp["head_sha"])
                or comp["base_sha"] != pr["base_sha"]
                or comp["head_sha"] != pr["head_sha"]):
            raise review.InvalidProposal("compare ref mismatch")
        file_count = pr["changed_files"]
        if type(file_count) is not int or not 1 <= file_count <= 64:
            raise review.InvalidProposal("PR file count")
        snapshots.append({
            "worker": entry["worker"], "branch": branch,
            "base_sha": pr["base_sha"], "head_sha": pr["head_sha"],
            "compare_status": comp["status"], "ahead_by": comp["ahead_by"],
            "behind_by": comp["behind_by"], "too_large": comp["too_large"],
            "expected_file_count": file_count, "files": comp["files"],
        })
    return json.dumps(
        {"version": 1, "base_sha": pin, "snapshots": snapshots},
        ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def check(raw: bytes) -> str:
    try:
        return adapter.check(_prepare(raw))
    except (review.InvalidProposal, UnicodeError, ValueError, TypeError,
            OverflowError, RecursionError, MemoryError):
        return "HOLD"


def main() -> int:
    try:
        status = check(sys.stdin.buffer.read(review.MAX_INPUT + 1))
    except (OSError, ValueError, MemoryError):
        status = "HOLD"
    sys.stdout.write(review._receipt(status) + "\n")
    return 3 if status == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
