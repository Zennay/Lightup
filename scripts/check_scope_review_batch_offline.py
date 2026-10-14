#!/usr/bin/env python3
"""Non-authorizing, opt-in OFFLINE all-or-nothing scope packet batch lint.

Not a consent, permit, grant, scan, CI, source-owner or release verifier.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys

import check_scope_review_packet_offline as single

MAX_BATCH_BYTES = 64 * 1024
MAX_PACKETS = 32


class BatchHold(ValueError):
    """Privacy-safe fixed denial reason, without user-supplied fields."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def validate_batch(packets: object) -> int:
    """Check metadata consistency, *never* independent or collective consent."""
    if type(packets) is not list or not 1 <= len(packets) <= MAX_PACKETS:
        raise BatchHold("BATCH_SHAPE")
    request_ids: set[str] = set()
    reference_tenant: dict[str, str] = {}
    evidence_tenant: dict[str, str] = {}
    by_asset: dict[tuple[str, str], list[tuple[str, str, frozenset[str]]]] = {}
    last_key: tuple[str, str, str] | None = None
    for packet in packets:
        try:
            single.validate_packet(packet)
        except single.PacketHold as exc:
            raise BatchHold("ITEM_" + exc.code) from None
        key = (packet["tenant_id"], packet["asset_id"], packet["request_id"])
        if last_key is not None and key <= last_key:
            raise BatchHold("BATCH_ORDER")
        last_key = key
        if packet["request_id"] in request_ids:
            raise BatchHold("DUPLICATE_REQUEST")
        request_ids.add(packet["request_id"])
        for reference in (packet["authorization_reference"], packet["scope_reference"]):
            previous = reference_tenant.setdefault(reference, packet["tenant_id"])
            if previous != packet["tenant_id"]:
                raise BatchHold("CROSS_TENANT_REFERENCE")
        for digest in packet["review_evidence_digests"]:
            previous = evidence_tenant.setdefault(digest, packet["tenant_id"])
            if previous != packet["tenant_id"]:
                raise BatchHold("CROSS_TENANT_EVIDENCE")
        asset_key = (packet["tenant_id"], packet["asset_id"])
        window = (packet["window_start"], packet["window_end"])
        capabilities = frozenset(packet["requested_capabilities"])
        for start, end, prior_capabilities in by_asset.get(asset_key, []):
            # Fixed-width, UTC-only ISO seconds permit lexical instant checks.
            # Review intervals are half-open; adjacent windows do not overlap.
            if start < window[1] and window[0] < end and capabilities & prior_capabilities:
                raise BatchHold("OVERLAPPING_ASSET_CAPABILITY")
        by_asset.setdefault(asset_key, []).append((*window, capabilities))
    return len(packets)


def evaluate(raw: bytes) -> dict[str, object]:
    status, reason, checked = "HOLD", "INVALID_BATCH", 0
    try:
        if type(raw) is not bytes or len(raw) > MAX_BATCH_BYTES:
            raise BatchHold("SIZE_LIMIT")
        try:
            decoded = single._decode(raw)
        except single.PacketHold as exc:
            raise BatchHold(exc.code) from None
        checked = validate_batch(decoded)
        status, reason = "REVIEW_ONLY", "SHAPE_ONLY_UNVERIFIED"
    except BatchHold as exc:
        checked = 0
        reason = exc.code
    return {
        "state": status, "reason": reason, "packets_checked": checked,
        "non_authorizing": True, **single.AUTHORITY_FLAGS,
    }


def read_batch_file(path: str) -> bytes:
    fd = None
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode):
            raise BatchHold("INPUT_UNAVAILABLE")
        if not stat.S_ISREG(before.st_mode):
            raise BatchHold("NOT_REGULAR_FILE")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BatchHold("NOT_REGULAR_FILE")
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns):
            raise BatchHold("CHANGED_INPUT")
        if info.st_size > MAX_BATCH_BYTES:
            raise BatchHold("SIZE_LIMIT")
        raw = os.read(fd, MAX_BATCH_BYTES + 1)
        if len(raw) > MAX_BATCH_BYTES:
            raise BatchHold("SIZE_LIMIT")
        if len(raw) != info.st_size:
            raise BatchHold("CHANGED_INPUT")
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns):
            raise BatchHold("CHANGED_INPUT")
        return raw
    except (OSError, OverflowError, ValueError) as exc:
        if isinstance(exc, BatchHold):
            raise
        raise BatchHold("INPUT_UNAVAILABLE") from None
    finally:
        if fd is not None:
            os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch_file", help="Local regular JSON array file only; never a URL or target")
    args = parser.parse_args(argv)
    try:
        receipt = evaluate(read_batch_file(args.batch_file))
    except BatchHold as exc:
        receipt = {"state": "HOLD", "reason": exc.code, "packets_checked": 0,
                   "non_authorizing": True, **single.AUTHORITY_FLAGS}
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["state"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
