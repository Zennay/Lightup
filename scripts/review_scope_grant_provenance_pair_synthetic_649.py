#!/usr/bin/env python3
"""Unwired comparison of *fictional* before/after grant provenance snapshots.

Do not treat a matching copy as authorization, independent provenance, consent,
or an execution permit. Neither snapshot is authenticated by this helper.
Only reads bounded stdin; never opens a database or contacts a real target.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Deliberately local opt-in offline reviewer, never a production import.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import review_scope_grant_provenance_synthetic_649 as base

PAIR_SCHEMA = "lightup.scope649.provenance_pair.synthetic.v1"
_PAIR_KEYS = frozenset({"before", "after"})
_TOP_KEYS = frozenset({"schema", "synthetic_only", "pairs"})
_PROVENANCE_KEYS = frozenset({"approved_by", "reference"})
MAX_PAIRS = base.MAX_ITEMS
MAX_INPUT = base.MAX_STDIN


def review_pair_batch(value: object) -> base.ReviewReceipt:
    """Only allow atomic shape/identity comparison of fictional paired records."""
    hold = base.ReviewReceipt(base.ReviewStatus.HOLD)
    if not base._has_exact_keys(value, _TOP_KEYS):
        return hold
    if type(value["schema"]) is not str or value["schema"] != PAIR_SCHEMA:
        return hold
    if value["synthetic_only"] is not True:
        return hold
    pairs = value["pairs"]
    if type(pairs) is not list or not 1 <= len(pairs) <= MAX_PAIRS:
        return hold
    seen_object_ids: set[int] = set()
    for pair in pairs:
        if not base._has_exact_keys(pair, _PAIR_KEYS):
            return hold
        before, after = pair["before"], pair["after"]
        # A duplicate in-memory object gives no separate synthetic snapshots.
        # This does not authenticate separately created but forged copies.
        own_ids = {id(pair), id(before), id(after)}
        if len(own_ids) != 3 or not seen_object_ids.isdisjoint(own_ids):
            return hold
        seen_object_ids.update(own_ids)
        if not base._has_exact_keys(before, _PROVENANCE_KEYS):
            return hold
        if not base._has_exact_keys(after, _PROVENANCE_KEYS):
            return hold
        for field in ("approved_by", "reference"):
            first, second = before[field], after[field]
            if not base._clean_text(first) or not base._clean_text(second):
                return hold
            if first != second:
                return hold
    return base.ReviewReceipt(base.ReviewStatus.REVIEW_ONLY)


def parse_and_compare(raw: object) -> base.ReviewReceipt:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_INPUT:
        return base.ReviewReceipt(base.ReviewStatus.HOLD)
    try:
        data = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=base._pairs_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return base.ReviewReceipt(base.ReviewStatus.HOLD)
    return review_pair_batch(data)


def main() -> int:
    """Privacy-minimal single stdout write, exit 2/3 only; NEVER authority."""
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        status = parse_and_compare(raw).status
    except (AttributeError, OSError, TypeError, ValueError):
        status = base.ReviewStatus.HOLD
    receipt = base._REVIEW_ONLY if status is base.ReviewStatus.REVIEW_ONLY else base._HOLD
    try:
        count = os.write(1, receipt)
        if type(count) is not int or count != len(receipt):
            return 2
    except (OSError, TypeError, ValueError):
        return 2
    return 3 if status is base.ReviewStatus.REVIEW_ONLY else 2


if __name__ == "__main__":
    sys.exit(main())
