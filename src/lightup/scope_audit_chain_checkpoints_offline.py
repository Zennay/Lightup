"""Strict offline chain of independently pinned fictional audit snapshots.

Never authenticates an anchor's origin or provides real consent, execution or
release authority. All trusted tips must arrive out-of-band, not from JSON.
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
    _strict_json_int,
    _unique_object,
    verify_chain,
)
from .scope_audit_chain_transition_offline import _canonical_packet

SCHEMA = "LIGHTUP-FICTIONAL-SCOPE-AUDIT-CHECKPOINTS-V1"
MAX_CHECKPOINTS = 8
MAX_INPUT_BYTES = MAX_BYTES * MAX_CHECKPOINTS + 4096
AUTHORITY_FALSE = {
    "consent_verified": False,
    "authorization_granted": False,
    "release_approved": False,
}


def _review_checkpoints(
    raw: bytes, trusted_tips: tuple[str, ...]
) -> tuple[int, int, int]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT_BYTES:
        raise InvalidChain("checkpoint input bound")
    if (
        type(trusted_tips) is not tuple
        or not 2 <= len(trusted_tips) <= MAX_CHECKPOINTS
        or any(not _hex(tip) for tip in trusted_tips)
    ):
        raise InvalidChain("external tip list")
    try:
        root = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_int=_strict_json_int,
        )
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise InvalidChain("checkpoint JSON") from exc

    if type(root) is not dict or frozenset(root) != {"schema", "snapshots"}:
        raise InvalidChain("checkpoint envelope")
    if type(root["schema"]) is not str or root["schema"] != SCHEMA:
        raise InvalidChain("checkpoint schema")
    snapshots = root["snapshots"]
    if (
        type(snapshots) is not list
        or len(snapshots) != len(trusted_tips)
        or not 2 <= len(snapshots) <= MAX_CHECKPOINTS
    ):
        raise InvalidChain("missing/extra checkpoint")

    previous_events = None
    first_count = 0
    for index, (snapshot, tip) in enumerate(zip(snapshots, trusted_tips)):
        serialized = _canonical_packet(snapshot)
        receipt = verify_chain(serialized, tip)
        if receipt["status"] != "REVIEW_ONLY":
            raise InvalidChain("checkpoint digest")
        events = snapshot["events"]
        if previous_events is None:
            first_count = len(events)
        elif (
            len(events) <= len(previous_events)
            or events[:len(previous_events)] != previous_events
        ):
            raise InvalidChain("checkpoint rewrite/rollback")
        previous_events = events
    assert previous_events is not None
    return len(snapshots), first_count, len(previous_events)


def verify_checkpoints(raw: bytes, trusted_tips: tuple[str, ...]) -> dict[str, object]:
    """Fail closed: review-only if EVERY external tip and prefix is coherent."""
    result = {
        "status": "HOLD",
        "checkpoints": 0,
        "initial_records": 0,
        "final_records": 0,
        "appended_records": 0,
        "reason": "CHECKPOINTS_INVALID",
        **AUTHORITY_FALSE,
    }
    try:
        count, initial, final = _review_checkpoints(raw, trusted_tips)
    except (InvalidChain, TypeError, ValueError, OverflowError, RecursionError):
        return result
    return {
        **result,
        "status": "REVIEW_ONLY",
        "checkpoints": count,
        "initial_records": initial,
        "final_records": final,
        "appended_records": final - initial,
        "reason": "FICTIONAL_CHECKPOINT_CONTINUITY",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Review fictional audit checkpoints; never grant authority"
    )
    parser.add_argument("--synthetic-only", action="store_true")
    parser.add_argument(
        "--expected-tip", action="append", required=True,
        help="Repeat in chronological order for EACH independently trusted snapshot",
    )
    args = parser.parse_args(argv)
    raw = (
        sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if args.synthetic_only else b""
    )
    receipt = verify_checkpoints(raw, tuple(args.expected_tip))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
