"""Bounded offline replay review for a *batch* of synthetic HMAC receipts.

An in-batch duplicate nonce/tip or out-of-order issue time produces HOLD.
No persistent replay registry exists; cross-batch replay remains UNSOLVED.
This does not authenticate real customers or grant any permission.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sys

from .scope_audit_anchor_auth_offline import (
    MAX_BYTES,
    InvalidAttestation,
    FALSE_FLAGS,
    _read_fd_secret,
    _unique_keys,
    _nonfinite,
    _now_utc,
    _valid_secret,
    _utc,
    verify_attestation,
)

SCHEMA = "LIGHTUP-FICTIONAL-AUDIT-TIP-MAC-BATCH-V1"
MAX_RECEIPTS = 32
MAX_BATCH_BYTES = MAX_RECEIPTS * MAX_BYTES + 4096


def _validate_batch(
    raw: bytes, secret: bytes, now: datetime, expected_key_id: str
) -> int:
    _valid_secret(secret)
    _now_utc(now)
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BATCH_BYTES:
        raise InvalidAttestation("batch bound")
    try:
        root = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_keys,
            parse_constant=_nonfinite,
        )
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise InvalidAttestation("malformed batch JSON") from exc
    if type(root) is not dict or frozenset(root) != {"schema", "attestations"}:
        raise InvalidAttestation("batch envelope")
    if type(root["schema"]) is not str or root["schema"] != SCHEMA:
        raise InvalidAttestation("batch schema")
    records = root["attestations"]
    if type(records) is not list or not 1 <= len(records) <= MAX_RECEIPTS:
        raise InvalidAttestation("batch count")
    seen_nonces: set[str] = set()
    seen_tips: set[str] = set()
    last_issued = None
    for record in records:
        if type(record) is not dict:
            raise InvalidAttestation("batch record shape")
        encoded = json.dumps(
            record, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        if verify_attestation(
            encoded, secret, now, expected_key_id,
        )["status"] != "REVIEW_ONLY":
            raise InvalidAttestation("unsigned, expired or untrusted receipt")
        nonce = record["nonce"]
        tip = record["tip_sha256"]
        issued = _utc(record["issued_at"])
        if nonce in seen_nonces or tip in seen_tips:
            raise InvalidAttestation("replayed nonce or tip in same batch")
        if last_issued is not None and issued <= last_issued:
            raise InvalidAttestation("receipt order")
        seen_nonces.add(nonce)
        seen_tips.add(tip)
        last_issued = issued
    return len(records)


def verify_batch(
    raw: bytes, secret: bytes, now: datetime, expected_key_id: str
) -> dict[str, object]:
    status = "HOLD"
    count = 0
    try:
        count = _validate_batch(raw, secret, now, expected_key_id)
        status = "REVIEW_ONLY"
    except (InvalidAttestation, TypeError, ValueError, OverflowError, RecursionError):
        pass
    return {
        "status": status,
        "records": count if status == "REVIEW_ONLY" else 0,
        "reason": (
            "FICTIONAL_BATCH_ONLY" if status == "REVIEW_ONLY" else "BATCH_INVALID"
        ),
        **FALSE_FLAGS,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Review a fictional HMAC batch, not real-world consent"
    )
    parser.add_argument("--synthetic-only", action="store_true")
    parser.add_argument("--expected-key-id", required=True)
    parser.add_argument("--key-fd", type=int, required=True)
    args = parser.parse_args(argv)
    raw = (
        sys.stdin.buffer.read(MAX_BATCH_BYTES + 1)
        if args.synthetic_only else b""
    )
    try:
        secret = _read_fd_secret(args.key_fd) if args.synthetic_only else b""
    except (OSError, InvalidAttestation):
        secret = b""
    result = verify_batch(
        raw, secret, datetime.now(timezone.utc), args.expected_key_id
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
