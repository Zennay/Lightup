"""Opt-in bounded stdin-only CLI for synthetic #1507 review; NEVER authorization.

Canonical ASCII JSON only. Exit 2 = fictional REVIEW_ONLY, 3 = HOLD.
Exit 0 is intentionally impossible. Does not log or echo source values.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import sys

from lightup.fictional_dual_party_review_1507 import (
    FictionalAcknowledgement,
    review_fictional_acknowledgements,
)


_LIMIT = 4096
_SCHEMA = "fictional_dual_party_v1"
_CLAIM_KEYS = frozenset((
    "case_id", "role", "actor_id", "asset", "capabilities", "risk",
    "issued_at", "expires_at", "decision", "revoked",
))


def _pairs_unique(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("duplicate")
        values[key] = value
    return values


def _reject_constant(_value):
    raise ValueError("constant")


def _utc(text):
    if type(text) is not str or len(text) != 20:
        raise ValueError("timestamp")
    instant = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    if instant.strftime("%Y-%m-%dT%H:%M:%SZ") != text:
        raise ValueError("timestamp")
    return instant.replace(tzinfo=timezone.utc)


def _claim(value):
    if type(value) is not dict or frozenset(value) != _CLAIM_KEYS:
        raise ValueError("fields")
    if type(value["capabilities"]) is not list:
        raise ValueError("capabilities")
    return FictionalAcknowledgement(
        case_id=value["case_id"],
        role=value["role"],
        actor_id=value["actor_id"],
        asset=value["asset"],
        capabilities=tuple(value["capabilities"]),
        risk=value["risk"],
        issued_at=_utc(value["issued_at"]),
        expires_at=_utc(value["expires_at"]),
        decision=value["decision"],
        revoked=value["revoked"],
    )


def _read_all():
    data = bytearray()
    while len(data) <= _LIMIT:
        part = sys.stdin.buffer.read(min(1024, _LIMIT + 1 - len(data)))
        if not part:
            break
        data.extend(part)
    if not data or len(data) > _LIMIT:
        raise ValueError("length")
    return bytes(data)


def _evaluate():
    data = _read_all()
    if not data.isascii():
        raise ValueError("ascii")
    decoded = data.decode("ascii")
    parsed = json.loads(
        decoded, object_pairs_hook=_pairs_unique, parse_constant=_reject_constant
    )
    if type(parsed) is not dict or frozenset(parsed) != frozenset(("schema", "review_at", "claims")):
        raise ValueError("envelope")
    if parsed["schema"] != _SCHEMA or type(parsed["schema"]) is not str:
        raise ValueError("schema")
    if type(parsed["claims"]) is not list or len(parsed["claims"]) != 2:
        raise ValueError("claims")
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if canonical != decoded:
        raise ValueError("not canonical")
    claims = tuple(_claim(record) for record in parsed["claims"])
    return review_fictional_acknowledgements(claims, _utc(parsed["review_at"])).status


def main():
    try:
        status = _evaluate()
    except Exception:
        status = "HOLD"
    if status != "REVIEW_ONLY":
        status = "HOLD"
    try:
        sys.stdout.write(status + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        return 3
    return 2 if status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
