"""Offline append-only continuity verification for fictional audit-chain exports.

Both independent SHA-256 tip anchors MUST be independently recorded/trusted.
The pure function verifies *content continuity*, not signatures, live scope,
human identity, consent, authorization or release approval.
"""

from __future__ import annotations

import argparse
import json
import sys

from .scope_audit_chain_offline import (
    InvalidChain,
    MAX_BYTES,
    _hex,
    _reject_constant,
    _unique_object,
    verify_chain,
)

SCHEMA = "LIGHTUP-FICTIONAL-SCOPE-AUDIT-TRANSITION-V1"
MAX_TRANSITION_BYTES = 2 * MAX_BYTES + 4096
ROOT_KEYS = frozenset({"schema", "before", "after"})
FALSE_AUTHORITY = {
    "consent_verified": False,
    "authorization_granted": False,
    "release_approved": False,
}


def _canonical_packet(value: object) -> bytes:
    """Create a bounded re-encoding; never normalize event values/types."""
    if type(value) is not dict:
        raise InvalidChain("packet object")
    try:
        result = json.dumps(
            value, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("ascii")
    except (ValueError, TypeError, OverflowError) as exc:
        raise InvalidChain("packet encoding") from exc
    if not 0 < len(result) <= MAX_BYTES:
        raise InvalidChain("packet bound")
    return result


def _review_transition(raw: bytes, old_tip: str, new_tip: str) -> tuple[int, int]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_TRANSITION_BYTES:
        raise InvalidChain("transition bound")
    if not _hex(old_tip) or not _hex(new_tip):
        raise InvalidChain("both externally anchored tips are required")
    try:
        root = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise InvalidChain("JSON") from exc
    if type(root) is not dict or frozenset(root) != ROOT_KEYS:
        raise InvalidChain("transition keys")
    if type(root["schema"]) is not str or root["schema"] != SCHEMA:
        raise InvalidChain("transition schema")
    before = root["before"]
    after = root["after"]
    before_bytes = _canonical_packet(before)
    after_bytes = _canonical_packet(after)
    previous_receipt = verify_chain(before_bytes, old_tip)
    proposed_receipt = verify_chain(after_bytes, new_tip)
    if previous_receipt["status"] != "REVIEW_ONLY":
        raise InvalidChain("previous tip mismatch")
    if proposed_receipt["status"] != "REVIEW_ONLY":
        raise InvalidChain("candidate tip mismatch")
    old_events = before["events"]
    next_events = after["events"]
    old_count = len(old_events)
    next_count = len(next_events)
    if not old_count < next_count:
        raise InvalidChain("must strictly append")
    if old_events != next_events[:old_count]:
        raise InvalidChain("prefix mismatch")
    return old_count, next_count


def verify_transition(raw: bytes, old_tip: str, new_tip: str) -> dict[str, object]:
    """Review only: both anchored chains must be valid and prefix-preserving."""
    previous_count, proposed_count = 0, 0
    status = "HOLD"
    try:
        previous_count, proposed_count = _review_transition(raw, old_tip, new_tip)
        status = "REVIEW_ONLY"
    except (InvalidChain, TypeError, ValueError, OverflowError, RecursionError):
        pass
    return {
        "status": status,
        "previous_records": previous_count if status == "REVIEW_ONLY" else 0,
        "proposed_records": proposed_count if status == "REVIEW_ONLY" else 0,
        "new_records": proposed_count - previous_count if status == "REVIEW_ONLY" else 0,
        "reason": (
            "FICTIONAL_APPEND_ONLY" if status == "REVIEW_ONLY"
            else "TRANSITION_INVALID"
        ),
        **FALSE_AUTHORITY,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify fictional append-only audit exports: NOT consent"
    )
    parser.add_argument("--synthetic-only", action="store_true")
    parser.add_argument("--expected-old-tip", required=True)
    parser.add_argument("--expected-new-tip", required=True)
    arguments = parser.parse_args(argv)
    raw = (
        sys.stdin.buffer.read(MAX_TRANSITION_BYTES + 1)
        if arguments.synthetic_only else b""
    )
    receipt = verify_transition(
        raw, arguments.expected_old_tip, arguments.expected_new_tip
    )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
