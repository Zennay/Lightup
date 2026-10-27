"""Pure offline continuity gate for fictional HMAC receipt replay ledgers.

This gate NEVER creates durable state and does not authenticate the old digest.
A separately trustworthy channel MUST pin the previous ledger SHA-256 before
any claimed cross-batch replay detection is meaningful. Nothing authorizes a
client, handler, grant, scan, deployment or actual security operation.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import sys

from .scope_audit_anchor_auth_offline import (
    FALSE_FLAGS, HEX, KEY_ID, NONCE, InvalidAttestation,
    _nonfinite, _now_utc, _read_fd_secret, _unique_keys, _utc, _valid_secret,
)
from .scope_audit_anchor_batch_offline import verify_batch, SCHEMA as BATCH_SCHEMA

SCHEMA = "LIGHTUP-FICTIONAL-MAC-REPLAY-UPDATE-V1"
LEDGER_SCHEMA = "LIGHTUP-FICTIONAL-MAC-REPLAY-LEDGER-V1"
DOMAIN = b"LIGHTUP-FICTIONAL-MAC-REPLAY-LEDGER-V1\x00"
MAX_LEDGER_ENTRIES = 256
MAX_UPDATE_BYTES = 524288
LEDGER_KEYS = frozenset({"schema", "key_id", "entries"})
ENTRY_KEYS = frozenset({"nonce", "tip_sha256", "issued_at"})
ROOT_KEYS = frozenset({"schema", "before", "after", "incoming"})


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    except (ValueError, TypeError, OverflowError) as exc:
        raise InvalidAttestation("noncanonical ledger JSON") from exc


def _ledger(ledger: object) -> list[dict[str, str]]:
    if type(ledger) is not dict or frozenset(ledger) != LEDGER_KEYS:
        raise InvalidAttestation("ledger keys")
    if type(ledger["schema"]) is not str or ledger["schema"] != LEDGER_SCHEMA:
        raise InvalidAttestation("ledger schema")
    key_id = ledger["key_id"]
    if type(key_id) is not str or KEY_ID.fullmatch(key_id) is None:
        raise InvalidAttestation("ledger signer identity")
    entries = ledger["entries"]
    if type(entries) is not list or len(entries) > MAX_LEDGER_ENTRIES:
        raise InvalidAttestation("ledger bounds")
    nonces: set[str] = set()
    tips: set[str] = set()
    last_time: datetime | None = None
    for entry in entries:
        if type(entry) is not dict or frozenset(entry) != ENTRY_KEYS:
            raise InvalidAttestation("ledger entry fields")
        nonce, tip = entry["nonce"], entry["tip_sha256"]
        if type(nonce) is not str or NONCE.fullmatch(nonce) is None:
            raise InvalidAttestation("ledger nonce shape")
        if type(tip) is not str or HEX.fullmatch(tip) is None:
            raise InvalidAttestation("ledger tip shape")
        instant = _utc(entry["issued_at"])
        if (
            nonce in nonces or tip in tips
            or (last_time is not None and instant <= last_time)
        ):
            raise InvalidAttestation("ledger replay/sequence")
        nonces.add(nonce)
        tips.add(tip)
        last_time = instant
    return entries


def compute_ledger_anchor(ledger: dict[str, object]) -> str:
    """Compute a candidate digest for separate trust-channel pinning; NOT trust."""
    _ledger(ledger)
    return hashlib.sha256(DOMAIN + _canonical(ledger)).hexdigest()


def _review(
    raw: bytes, trusted_previous_tip: str, secret: bytes,
    now: datetime, expected_key_id: str,
) -> tuple[int, int]:
    _valid_secret(secret)
    _now_utc(now)
    if type(expected_key_id) is not str or KEY_ID.fullmatch(expected_key_id) is None:
        raise InvalidAttestation("trusted key identity")
    if (
        type(trusted_previous_tip) is not str
        or HEX.fullmatch(trusted_previous_tip) is None
    ):
        raise InvalidAttestation("trusted ledger anchor required")
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_UPDATE_BYTES:
        raise InvalidAttestation("update input bound")
    try:
        root = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_keys,
            parse_constant=_nonfinite,
        )
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise InvalidAttestation("malformed update JSON") from exc
    if type(root) is not dict or frozenset(root) != ROOT_KEYS:
        raise InvalidAttestation("update fields")
    if type(root["schema"]) is not str or root["schema"] != SCHEMA:
        raise InvalidAttestation("update schema")
    before, after = root["before"], root["after"]
    old_entries = _ledger(before)
    new_entries = _ledger(after)
    if (
        before["key_id"] != expected_key_id
        or after["key_id"] != expected_key_id
    ):
        raise InvalidAttestation("ledger signer mismatch")
    old_anchor = compute_ledger_anchor(before)
    if not hmac.compare_digest(old_anchor, trusted_previous_tip):
        raise InvalidAttestation("previous ledger is not externally anchored")
    old_size, new_size = len(old_entries), len(new_entries)
    if not old_size < new_size:
        raise InvalidAttestation("not an append")
    if new_entries[:old_size] != old_entries:
        raise InvalidAttestation("history changed")
    batch = root["incoming"]
    if type(batch) is not dict or batch.get("schema") != BATCH_SCHEMA:
        raise InvalidAttestation("signed receipt batch required")
    batch_receipt = verify_batch(
        _canonical(batch), secret, now, expected_key_id,
    )
    if batch_receipt["status"] != "REVIEW_ONLY":
        raise InvalidAttestation("new receipts not authentically MAC-checked")
    expected_entries = [
        {field: receipt[field] for field in ENTRY_KEYS}
        for receipt in batch["attestations"]
    ]
    if new_entries[old_size:] != expected_entries:
        raise InvalidAttestation("candidate ledger omits/changes signed receipts")
    return old_size, new_size


def verify_replay_update(
    raw: bytes, trusted_previous_tip: str, secret: bytes,
    now: datetime, expected_key_id: str,
) -> dict[str, object]:
    """Review-only; requires prior ledger tip from a REAL independent source."""
    status = "HOLD"
    before_count = after_count = 0
    try:
        before_count, after_count = _review(
            raw, trusted_previous_tip, secret, now, expected_key_id
        )
        status = "REVIEW_ONLY"
    except (InvalidAttestation, ValueError, TypeError, OverflowError, RecursionError):
        pass
    return {
        "status": status,
        "previous_records": before_count if status == "REVIEW_ONLY" else 0,
        "proposed_records": after_count if status == "REVIEW_ONLY" else 0,
        "appended_records": after_count - before_count if status == "REVIEW_ONLY" else 0,
        "reason": (
            "FICTIONAL_REPLAY_CONTINUITY_ONLY" if status == "REVIEW_ONLY"
            else "REPLAY_UPDATE_INVALID"
        ),
        **FALSE_FLAGS,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an independently pinned fictional MAC replay ledger"
    )
    parser.add_argument("--synthetic-only", action="store_true")
    parser.add_argument("--expected-key-id", required=True)
    parser.add_argument("--expected-ledger-tip", required=True)
    parser.add_argument("--key-fd", type=int, required=True)
    args = parser.parse_args(argv)
    raw = (
        sys.stdin.buffer.read(MAX_UPDATE_BYTES + 1)
        if args.synthetic_only else b""
    )
    try:
        secret = _read_fd_secret(args.key_fd) if args.synthetic_only else b""
    except (OSError, InvalidAttestation):
        secret = b""
    result = verify_replay_update(
        raw, args.expected_ledger_tip, secret,
        datetime.now(timezone.utc), args.expected_key_id,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
