"""Offline two-party scope-claim review. NEVER an authorization or execution gate.

No signature or actor authentication is performed here. The output is explicitly
non-authorizing even when a fictional/synthetic packet is internally consistent.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta, timezone

MAX_INPUT_BYTES = 32 * 1024
MAX_REVOCATIONS = 32
MAX_CONSENT_LIFETIME = timedelta(hours=24)
MAX_CONSENT_SKEW = timedelta(minutes=15)
OID = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
PRINCIPAL = re.compile(r"(?:client|operator):[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)

AUTHORITY_FLAGS = {
    "authorize": False, "grant": False, "scan": False,
    "handler": False, "dispatch": False, "merge": False,
    "deploy": False, "release": False,
}


class PacketError(ValueError):
    pass


def _fail(_message: str) -> None:
    raise PacketError("invalid_packet")


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            _fail("duplicate field")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    _fail("nonfinite number")


def _exact_dict(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        _fail("schema mismatch")
    return value


def _text(value: object, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        _fail("noncanonical identity")
    return value


def _seq(value: object) -> int:
    if type(value) is not int or value < 1 or value > 65535:
        _fail("invalid sequence")
    return value


def _utc(value: object) -> datetime:
    if type(value) is not str or len(value) != 20:
        _fail("invalid timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        _fail("invalid timestamp")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail("noncanonical timestamp")
    return parsed


def _claim(record: dict[str, object], proposal: str, scope: str) -> tuple[str, str]:
    role = record["role"]
    if type(role) is not str or role not in ("client", "operator"):
        _fail("invalid role")
    principal = _text(record["principal"], PRINCIPAL)
    if not principal.startswith(role + ":"):
        _fail("principal role mismatch")
    if record["proposal_sha"] != proposal or record["scope_sha256"] != scope:
        _fail("scope/proposal drift")
    return role, principal


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_INPUT_BYTES:
        _fail("unbounded or invalid input")
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _fail("invalid JSON")
    _exact_dict(payload, {"schema_version", "proposal_sha", "scope_sha256", "review_at", "consents", "revocations"})
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        _fail("schema version")
    proposal = _text(payload["proposal_sha"], OID)
    scope = _text(payload["scope_sha256"], DIGEST)
    if proposal == "0" * 40 or scope == "0" * 64:
        _fail("null identities")
    review_at = _utc(payload["review_at"])

    consents = payload["consents"]
    revocations = payload["revocations"]
    if type(consents) is not list or len(consents) != 2:
        _fail("two consent records required")
    if type(revocations) is not list or len(revocations) > MAX_REVOCATIONS:
        _fail("invalid revocations")

    actors: dict[str, str] = {}
    issued: list[datetime] = []
    event_order: list[tuple[int, datetime, str, str]] = []
    for record in consents:
        _exact_dict(record, {"role", "principal", "proposal_sha", "scope_sha256", "issued_at", "expires_at", "event_seq"})
        role, principal = _claim(record, proposal, scope)
        if role in actors or principal in actors.values():
            _fail("duplicate principal/role")
        actors[role] = principal
        start, end = _utc(record["issued_at"]), _utc(record["expires_at"])
        if not start <= review_at < end or not timedelta(0) < end - start <= MAX_CONSENT_LIFETIME:
            _fail("stale/invalid consent")
        issued.append(start)
        event_order.append((_seq(record["event_seq"]), start, role, "consent"))
    if set(actors) != {"client", "operator"}:
        _fail("missing role")
    if max(issued) - min(issued) > MAX_CONSENT_SKEW:
        _fail("approval skew")

    for record in revocations:
        _exact_dict(record, {"role", "principal", "proposal_sha", "scope_sha256", "effective_at", "event_seq"})
        role, principal = _claim(record, proposal, scope)
        if actors.get(role) != principal:
            _fail("unknown revoking principal")
        effective = _utc(record["effective_at"])
        if effective > review_at:
            _fail("future revocation cannot be evidenced")
        event_order.append((_seq(record["event_seq"]), effective, role, "revocation"))

    events = sorted(event_order)
    if len({row[0] for row in events}) != len(events):
        _fail("replayed event sequence")
    # An input with later sequence numbers but earlier timestamps is ambiguous.
    if any(left[1] > right[1] for left, right in zip(events, events[1:])):
        _fail("backdated event ordering")
    role_issuance = {row[2]: row[1] for row in events if row[3] == "consent"}
    if any(row[3] == "revocation" and row[1] < role_issuance[row[2]] for row in events):
        _fail("revoked before consent")
    if revocations:
        _fail("revocation present")
    return payload


def review(raw: bytes) -> dict[str, object]:
    """Consistency-only review. NEVER returns authority, including on valid input."""
    try:
        _parse(raw)
    except (PacketError, OverflowError, MemoryError):
        return {"schema_version": 1, "status": "HOLD", "reason": "INVALID_OR_REVOKED", **AUTHORITY_FLAGS}
    return {"schema_version": 1, "status": "REVIEW_ONLY", "reason": "UNAUTHENTICATED_CLAIMS_ONLY", **AUTHORITY_FLAGS}


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        output = {"schema_version": 1, "status": "HOLD", "reason": "INVALID_OR_REVOKED", **AUTHORITY_FLAGS}
    else:
        try:
            parts = []
            length = 0
            while True:
                chunk = sys.stdin.buffer.read(min(4096, MAX_INPUT_BYTES + 1 - length))
                if type(chunk) is not bytes:
                    _fail("non-byte input")
                if not chunk:
                    break
                length += len(chunk)
                if length > MAX_INPUT_BYTES:
                    _fail("oversized input")
                parts.append(chunk)
            output = review(b"".join(parts))
        except (OSError, PacketError, ValueError, MemoryError, OverflowError):
            output = {"schema_version": 1, "status": "HOLD", "reason": "INVALID_OR_REVOKED", **AUTHORITY_FLAGS}
    try:
        wire = json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n"
        count = sys.stdout.write(wire)
        sys.stdout.flush()
        if type(count) is not int or count != len(wire):
            return 2
    except (OSError, ValueError, UnicodeError):
        return 2
    return 3 if output["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
