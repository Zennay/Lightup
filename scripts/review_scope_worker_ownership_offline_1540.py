"""Offline owner-path overlay for #1540. Not authorization or GitHub evidence.

Inputs are entirely caller-controlled and have NO provenance. A syntactically
consistent preview is advisory REVIEW_ONLY, never consent/GO or a merge permit.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

_SIBLING = Path(__file__).resolve().with_name(
    "review_scope_pr_compare_pair_offline_1540.py")
_spec = importlib.util.spec_from_file_location("scope1540_pair_owner", _SIBLING)
pair = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pair)
review = pair.review
adapter = pair.adapter

_ROOT = {"version", "repository_full_name", "base_sha", "reviews",
         "ownership", "protected_paths"}
_OWNER = {"worker", "head_sha", "paths"}


def _conflict(a: str, b: str) -> bool:
    a, b = a.casefold(), b.casefold()
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def _prepare(raw: bytes) -> bytes:
    incoming = review._canonical_decode(raw)
    if type(incoming) is not dict or set(incoming) != _ROOT:
        raise review.InvalidProposal("ownership schema")
    root = {key: incoming[key] for key in ("version", "repository_full_name",
                                         "base_sha", "reviews")}
    pair_raw = json.dumps(root, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":")).encode("ascii")
    if pair.check(pair_raw) != "REVIEW_ONLY":
        raise review.InvalidProposal("PR/compare HOLD")

    # Reuse the two existing strictly bounded parse/admission stages. Neither
    # imports LightUp production, reads git or performs network operations.
    normalized = review._canonical_decode(adapter._convert(pair._prepare(pair_raw)))
    proposals = normalized["proposals"]
    claims = incoming["ownership"]
    if type(claims) is not list or len(claims) != len(proposals):
        raise review.InvalidProposal("owner inventory count")

    by_worker = {}
    for claim in claims:
        if type(claim) is not dict or set(claim) != _OWNER:
            raise review.InvalidProposal("owner claim fields")
        worker, head, paths = claim["worker"], claim["head_sha"], claim["paths"]
        if (type(worker) is not str
                or review.WORKER.fullmatch(worker) is None
                or worker in by_worker or not adapter._sha(head)
                or type(paths) is not list or not 1 <= len(paths) <= 128):
            raise review.InvalidProposal("owner claim identity")
        exact, fold = set(), set()
        for path in paths:
            if not review._safe_path(path):
                raise review.InvalidProposal("owned path")
            if path in exact or path.casefold() in fold:
                raise review.InvalidProposal("duplicate owned path")
            exact.add(path)
            fold.add(path.casefold())
        by_worker[worker] = (head, exact)

    protected = incoming["protected_paths"]
    if type(protected) is not list or not 1 <= len(protected) <= 64:
        raise review.InvalidProposal("protected inventory")
    prefix_index = review._PathIndex()
    for path in protected:
        if not review._safe_path(path) or not prefix_index.add(path):
            raise review.InvalidProposal("ambiguous protected path")

    source = incoming["reviews"]
    for item, claimed in zip(source, proposals):
        worker = claimed["worker"]
        if worker not in by_worker:
            raise review.InvalidProposal("unassigned worker")
        head, declared = by_worker[worker]
        if head != item["pr"]["head_sha"]:
            raise review.InvalidProposal("unbound ownership claim")
        actual = set()
        for change in claimed["changes"]:
            actual.add(change["path"])
            if "from_path" in change:
                actual.add(change["from_path"])
        # Exact byte-for-byte identity, not case-folded equivalence: a claim
        # must account for every changed filename and both rename endpoints.
        if actual != declared:
            raise review.InvalidProposal("unaccounted or invented file")
        for path in actual:
            if any(_conflict(path, p) for p in protected):
                raise review.InvalidProposal("protected source collision")
    return pair_raw


def check(raw: bytes) -> str:
    try:
        return pair.check(_prepare(raw))
    except (review.InvalidProposal, UnicodeError, ValueError, TypeError,
            OverflowError, RecursionError, MemoryError):
        return "HOLD"


def main() -> int:
    try:
        result = check(sys.stdin.buffer.read(review.MAX_INPUT + 1))
    except (OSError, ValueError, MemoryError):
        result = "HOLD"
    sys.stdout.write(review._receipt(result) + "\n")
    return 3 if result == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
