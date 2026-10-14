#!/usr/bin/env python3
"""Offline comparison of two review-batch shapes. NEVER a scope authorization.

REVIEW_ONLY says a proposed untrusted review packet set is a non-widening
syntactic subset of an earlier untrusted set, not that either set was permitted.
No active executor, target access, grant verification, network or persistence.
"""
from __future__ import annotations

import argparse
import json
import sys

import check_scope_review_batch_offline as batch
import check_scope_review_packet_offline as single


class DeltaHold(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _validate(raw: bytes) -> list[dict[str, object]]:
    if type(raw) is not bytes or len(raw) > batch.MAX_BATCH_BYTES:
        raise DeltaHold("SIZE_LIMIT")
    try:
        items = single._decode(raw)
        batch.validate_batch(items)
    except single.PacketHold as exc:
        raise DeltaHold(exc.code) from None
    except batch.BatchHold as exc:
        raise DeltaHold(exc.code) from None
    return items


def compare(previous_raw: bytes, proposed_raw: bytes) -> dict[str, object]:
    """Conservatively reject additions, provenance drift and scope expansion.

    Both snapshots are only caller-provided metadata. This function must never
    be used to admit or enable any actual target-active tool execution.
    """
    state, reason = "HOLD", "INVALID_DELTA"
    retained = narrowed = removed = 0
    try:
        previous = _validate(previous_raw)
        proposed = _validate(proposed_raw)
        old_by_id = {record["request_id"]: record for record in previous}
        retained = len(proposed)
        removed = len(previous) - retained
        if removed < 0:
            raise DeltaHold("ADDED_REQUEST")
        for record in proposed:
            original = old_by_id.get(record["request_id"])
            if original is None:
                raise DeltaHold("ADDED_REQUEST")
            for field in ("tenant_id", "asset_id", "requester_id"):
                if record[field] != original[field]:
                    raise DeltaHold("IDENTITY_CHANGED")
            for field in ("authorization_reference", "scope_reference", "review_evidence_digests"):
                if record[field] != original[field]:
                    raise DeltaHold("PROVENANCE_CHANGED")
            if record["requested_mode"] != original["requested_mode"]:
                # Mode is not a numeric authority hierarchy. All changes HOLD.
                raise DeltaHold("MODE_CHANGED")
            if record["risk_level"] > original["risk_level"]:
                raise DeltaHold("RISK_WIDENED")
            if not set(record["requested_capabilities"]).issubset(original["requested_capabilities"]):
                raise DeltaHold("CAPABILITY_WIDENED")
            if (record["window_start"] < original["window_start"]
                    or record["window_end"] > original["window_end"]):
                # Both rows already passed exact seconds-resolution UTC parsing.
                raise DeltaHold("WINDOW_WIDENED")
            if record != original:
                narrowed += 1
        state, reason = "REVIEW_ONLY", "SYNTAX_ONLY_UNVERIFIED"
    except DeltaHold as exc:
        state, reason = "HOLD", exc.code
        retained = narrowed = removed = 0
    return {
        "state": state, "reason": reason,
        "retained_requests": retained, "removed_requests": removed,
        "narrowed_requests": narrowed, "non_authorizing": True,
        **single.AUTHORITY_FLAGS,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous_file", help="Local regular JSON batch; not a permit")
    parser.add_argument("proposed_file", help="Local regular JSON batch; not a permit")
    parser.add_argument("--require-private-file", action="store_true",
                        help="Require owner-only POSIX file checks for both local snapshots")
    args = parser.parse_args(argv)
    try:
        old = batch.read_batch_file(args.previous_file,
                                    require_private_file=args.require_private_file)
        proposed = batch.read_batch_file(args.proposed_file,
                                         require_private_file=args.require_private_file)
        result = compare(old, proposed)
    except batch.BatchHold as exc:
        result = {
            "state": "HOLD", "reason": exc.code,
            "retained_requests": 0, "removed_requests": 0,
            "narrowed_requests": 0, "non_authorizing": True,
            **single.AUTHORITY_FLAGS,
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["state"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
