"""Bounded, non-authorizing offline integrity review for fictional scope audit chains.

This does not authenticate a real party, consent, revocation, or execution rights.
The expected tip MUST originate from an independent trusted channel; the caller's
assertion about its origin cannot be verified by this module.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import hmac
import json
import re
import sys

SCHEMA = "LIGHTUP-FICTIONAL-SCOPE-AUDIT-CHAIN-V1"
DOMAIN = b"LIGHTUP-FICTIONAL-SCOPE-AUDIT-CHAIN-V1\x00"
MAX_BYTES = 32768
MAX_EVENTS = 64
ZERO_HASH = "0" * 64
HEX_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
EVENT_KEYS = frozenset(
    {"seq", "kind", "at", "scope_sha256", "previous_sha256", "sha256"}
)
BODY_KEYS = frozenset(EVENT_KEYS - {"sha256"})
ALLOWED_KINDS = frozenset({"REVIEW_OPENED", "REVIEW_NOTE", "REVIEW_WITHDRAWN"})


class InvalidChain(ValueError):
    """One or more fictional audit-chain inputs are invalid."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidChain("duplicate key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise InvalidChain("nonfinite numeric constant")


def _hex(value: object) -> bool:
    return type(value) is str and HEX_HASH.fullmatch(value) is not None


def _utc(value: object) -> datetime:
    if type(value) is not str or len(value) != 20:
        raise InvalidChain("timestamp shape")
    try:
        instant = datetime.strptime(value, TIME_FORMAT)
    except ValueError as exc:
        raise InvalidChain("timestamp") from exc
    if instant.strftime(TIME_FORMAT) != value:
        raise InvalidChain("noncanonical timestamp")
    return instant


def compute_event_hash(event_body: dict[str, object]) -> str:
    """Hash a validated fictional record *body* (does not grant authority).

    The body must be a plain dict with the exact five fixed keys. The verifier
    separately validates values; this helper is provided for local fixtures.
    """
    if type(event_body) is not dict or frozenset(event_body) != BODY_KEYS:
        raise InvalidChain("event body fields")
    try:
        canonical = json.dumps(
            event_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise InvalidChain("noncanonical body") from exc
    return hashlib.sha256(DOMAIN + canonical).hexdigest()


def _review(raw: bytes, expected_tip: str) -> int:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise InvalidChain("input bound")
    if not _hex(expected_tip):
        raise InvalidChain("expected tip required")
    try:
        root = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise InvalidChain("invalid JSON") from exc
    if type(root) is not dict or frozenset(root) != {"schema", "events"}:
        raise InvalidChain("root fields")
    if type(root["schema"]) is not str or root["schema"] != SCHEMA:
        raise InvalidChain("schema")
    events = root["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise InvalidChain("event count")
    previous = ZERO_HASH
    scope = None
    last_at = None
    withdrawn = False
    for index, event in enumerate(events):
        if type(event) is not dict or frozenset(event) != EVENT_KEYS:
            raise InvalidChain("event fields")
        if type(event["seq"]) is not int or event["seq"] != index:
            raise InvalidChain("event order")
        kind = event["kind"]
        if type(kind) is not str or kind not in ALLOWED_KINDS:
            raise InvalidChain("event kind")
        if (index == 0) != (kind == "REVIEW_OPENED"):
            raise InvalidChain("review must open exactly once at the start")
        if withdrawn:
            raise InvalidChain("record after withdrawal")
        if kind == "REVIEW_WITHDRAWN":
            withdrawn = True
        instant = _utc(event["at"])
        if last_at is not None and instant <= last_at:
            raise InvalidChain("nonmonotonic timestamp")
        last_at = instant
        event_scope = event["scope_sha256"]
        if not _hex(event_scope):
            raise InvalidChain("scope digest")
        if scope is None:
            scope = event_scope
        elif not hmac.compare_digest(scope, event_scope):
            raise InvalidChain("scope changed")
        if not _hex(event["previous_sha256"]) or not hmac.compare_digest(
            event["previous_sha256"], previous
        ):
            raise InvalidChain("broken predecessor")
        if not _hex(event["sha256"]):
            raise InvalidChain("event digest")
        body = {key: event[key] for key in BODY_KEYS}
        computed = compute_event_hash(body)
        if not hmac.compare_digest(event["sha256"], computed):
            raise InvalidChain("tampered event")
        previous = computed
    if not hmac.compare_digest(previous, expected_tip):
        raise InvalidChain("external anchor mismatch")
    return len(events)


def verify_chain(raw: bytes, expected_tip: str) -> dict[str, object]:
    """Return fixed HOLD or REVIEW_ONLY; never return consent or approval."""
    status = "HOLD"
    count = 0
    try:
        count = _review(raw, expected_tip)
        status = "REVIEW_ONLY"
    except (InvalidChain, TypeError, ValueError, RecursionError):
        pass
    return {
        "status": status,
        "records": count if status == "REVIEW_ONLY" else 0,
        "consent_verified": False,
        "authorization_granted": False,
        "release_approved": False,
        "reason": "FICTIONAL_CHAIN_ONLY" if status == "REVIEW_ONLY" else "CHAIN_INVALID",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline fictional audit-chain integrity, NEVER authorization"
    )
    parser.add_argument("--synthetic-only", action="store_true")
    parser.add_argument("--expected-tip", required=True)
    args = parser.parse_args(argv)
    if not args.synthetic_only:
        result = verify_chain(b"", args.expected_tip)
    else:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        result = verify_chain(raw, args.expected_tip)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
