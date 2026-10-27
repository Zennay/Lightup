#!/usr/bin/env python3
"""Opt-in cross-file offline scope review consistency; NEVER grants authority.

Validating two previously saved review snapshots is not verifying their provenance,
freshness, customer consent or whether a production runner may dispatch any target.
"""
from __future__ import annotations

import argparse
import json
import sys

import check_scope_review_packet_offline as single
import check_scope_review_batch_offline as batch

MAX_FILES = 4
MAX_ITEMS = 32
MAX_TOTAL_BYTES = 128 * 1024


class CrossFileHold(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def inspect_files(raw_files: object, *, include_summary: bool = False) -> dict[str, object]:
    """Fail closed atomically for all files; do not echo their names or contents."""
    state, reason, count, files = "HOLD", "INVALID_SNAPSHOTS", 0, 0
    mode_counts = {mode: 0 for mode in sorted(single.MODES)}
    risk_counts = {str(risk): 0 for risk in range(6)}
    try:
        if type(include_summary) is not bool:
            raise CrossFileHold("INVALID_SUMMARY_POLICY")
        if type(raw_files) is not tuple or not 2 <= len(raw_files) <= MAX_FILES:
            raise CrossFileHold("FILE_COUNT")
        if any(type(raw) is not bytes for raw in raw_files):
            raise CrossFileHold("INVALID_FILE_BYTES")
        if any(len(raw) > batch.MAX_BATCH_BYTES for raw in raw_files) or sum(map(len, raw_files)) > MAX_TOTAL_BYTES:
            raise CrossFileHold("SIZE_LIMIT")
        merged: list[dict[str, object]] = []
        for raw in raw_files:
            try:
                decoded = single._decode(raw)
                # Each snapshot must already be individually well-formed, never
                # absorb a dirty historical snapshot into a clean combined list.
                batch.validate_batch(decoded)
            except single.PacketHold as exc:
                raise CrossFileHold(exc.code) from None
            except batch.BatchHold as exc:
                raise CrossFileHold(exc.code) from None
            merged.extend(decoded)
            if len(merged) > MAX_ITEMS:
                raise CrossFileHold("TOTAL_ITEMS")
        # Snapshots are separately sorted; combining them lexically checks
        # cross-file conflicts independently of the order files were supplied.
        merged.sort(key=lambda x: (x["tenant_id"], x["asset_id"], x["request_id"]))
        try:
            count = batch.validate_batch(merged)
        except batch.BatchHold as exc:
            raise CrossFileHold(exc.code) from None
        if include_summary:
            for item in merged:
                mode_counts[item["requested_mode"]] += 1
                risk_counts[str(item["risk_level"])] += 1
        state, reason, files = "REVIEW_ONLY", "SHAPE_ONLY_UNVERIFIED", len(raw_files)
    except CrossFileHold as exc:
        state, reason, count, files = "HOLD", exc.code, 0, 0
    receipt: dict[str, object] = {
        "state": state, "reason": reason,
        "packets_checked": count, "files_checked": files,
        "non_authorizing": True, **single.AUTHORITY_FLAGS,
    }
    if include_summary is True:
        receipt.update(mode_counts=mode_counts, risk_counts=risk_counts)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch_files", nargs="+", help="2–4 local JSON snapshot files; no URLs")
    parser.add_argument("--require-private-file", action="store_true",
                        help="Require owner-only, one-link POSIX file privacy checks for every snapshot")
    parser.add_argument("--summary", action="store_true",
                        help="Optional cross-file aggregate mode/risk counts, always zero on HOLD")
    args = parser.parse_args(argv)

    if not 2 <= len(args.batch_files) <= MAX_FILES:
        receipt = inspect_files(tuple(), include_summary=args.summary)
    else:
        try:
            # Input paths are deliberately never added to the response. The
            # underlying reader closes the descriptor and refuses unsafe types.
            raw_files = tuple(batch.read_batch_file(path, require_private_file=args.require_private_file)
                              for path in args.batch_files)
            receipt = inspect_files(raw_files, include_summary=args.summary)
        except batch.BatchHold as exc:
            receipt = inspect_files(tuple(), include_summary=args.summary)
            receipt["reason"] = exc.code
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["state"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
