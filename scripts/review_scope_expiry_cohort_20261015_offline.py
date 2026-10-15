"""Non-authorizing, offline expiry-cohort review of UNTRUSTED UTC window claims.

No client identifiers, targets, risk approvals, resolvers, clocks or credentials are
accepted. This module is intentionally NOT imported by production authorization.
Every exit is nonzero; every authority-related output bit is literally false.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta, timezone

MAX_INPUT_BYTES = 16 * 1024
MAX_CLAIMS = 32
UTC_PATTERN = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})Z",
    flags=re.ASCII,
)
DENIAL_FLAGS = {
    "authorization_verified": False,
    "permit_issued": False,
    "dispatch_enabled": False,
    "merge_approved": False,
    "deploy_approved": False,
    "release_approved": False,
}


def _reject_constant(_value: str) -> None:
    raise ValueError("invalid JSON constant")


def _parse_int(raw: str) -> int:
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,3})", raw, flags=re.ASCII):
        raise ValueError("noncanonical JSON integer")
    return int(raw)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _utc(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("UTC timestamp must be a built-in string")
    match = UTC_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError("noncanonical UTC timestamp")
    year, month, day, hour, minute, second = map(int, match.groups())
    # Explicit construction refuses 24:00:00 even where some Python versions
    # normalize ISO 24:00:00 into a DIFFERENT calendar day.
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def review(payload: bytes) -> dict[str, object]:
    """Classify claim windows, never confer authorization or release."""
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_INPUT_BYTES:
        raise ValueError("invalid payload size/type")
    doc = json.loads(
        payload.decode("utf-8", errors="strict"),
        object_pairs_hook=_unique_object,
        parse_int=_parse_int,
        parse_float=_reject_constant,
        parse_constant=_reject_constant,
    )
    if type(doc) is not dict or set(doc) != {
        "as_of_utc", "horizon_hours", "windows"
    }:
        raise ValueError("invalid top-level shape")
    as_of = _utc(doc["as_of_utc"])
    hours = doc["horizon_hours"]
    if type(hours) is not int or not 1 <= hours <= 720:
        raise ValueError("invalid horizon")
    windows = doc["windows"]
    if type(windows) is not list or not 1 <= len(windows) <= MAX_CLAIMS:
        raise ValueError("invalid cohort")
    counts = {
        "expired": 0,
        "not_yet_started": 0,
        "current_expiring_within_horizon": 0,
        "current_later": 0,
    }
    horizon = timedelta(hours=hours)
    for claim in windows:
        if type(claim) is not dict or set(claim) != {"valid_from", "valid_until"}:
            raise ValueError("invalid window shape")
        start = _utc(claim["valid_from"])
        end = _utc(claim["valid_until"])
        if end <= start:
            raise ValueError("empty/inverted authorization window")
        if as_of > end:  # Producer's durable validity end is INCLUSIVE.
            counts["expired"] += 1
        elif as_of < start:
            counts["not_yet_started"] += 1
        elif end - as_of <= horizon:
            counts["current_expiring_within_horizon"] += 1
        else:
            counts["current_later"] += 1
    return {"status": "REVIEW_ONLY", **counts, **DENIAL_FLAGS}


def _receipt(status: str) -> dict[str, object]:
    return {"status": status, **DENIAL_FLAGS}


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        if argv:
            raise ValueError("unexpected CLI arguments")
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        result = review(data)
        code = 3
    except (ValueError, TypeError, UnicodeError, OverflowError, OSError, RecursionError):
        result = _receipt("HOLD")
        code = 2
    # Fixed-schema aggregate-only output; no client/target/timestamp echoes.
    sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=True) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
