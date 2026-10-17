"""Offline, non-authorizing HMAC-SHA256 attestation of fictional audit tips.

This verifies only possession of out-of-band symmetric key material. It does
NOT verify a person's identity, the key's real-world owner, client consent,
revocation, an authorized scope, or any runtime execution permissions.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import re
import sys

SCHEMA = "LIGHTUP-FICTIONAL-AUDIT-TIP-MAC-V1"
DOMAIN = b"LIGHTUP-FICTIONAL-AUDIT-TIP-MAC-V1\x00"
MAX_BYTES = 8192
MIN_KEY_BYTES = 32
MAX_KEY_BYTES = 64
MAX_LIFETIME = timedelta(hours=24)
FUTURE_SKEW = timedelta(minutes=5)
HEX = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
NONCE = re.compile(r"[a-f0-9]{32}\Z", re.ASCII)
KEY_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z", re.ASCII)
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
FIELDS = frozenset({
    "schema", "key_id", "tip_sha256", "nonce",
    "issued_at", "expires_at", "mac_sha256",
})
BODY_FIELDS = frozenset(FIELDS - {"mac_sha256"})
FALSE_FLAGS = {
    "consent_verified": False,
    "authorization_granted": False,
    "release_approved": False,
}


class InvalidAttestation(ValueError):
    """A fictional attestation is malformed or unverifiable."""


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidAttestation("duplicate key")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise InvalidAttestation("nonfinite JSON number")


def _utc(value: object) -> datetime:
    if type(value) is not str or len(value) != 20:
        raise InvalidAttestation("timestamp shape")
    try:
        parsed = datetime.strptime(value, TIME_FORMAT)
    except ValueError as exc:
        raise InvalidAttestation("invalid timestamp") from exc
    if parsed.strftime(TIME_FORMAT) != value:
        raise InvalidAttestation("noncanonical timestamp")
    return parsed.replace(tzinfo=timezone.utc)


def _now_utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise InvalidAttestation("explicit UTC clock required")
    return value


def _valid_secret(value: object) -> bytes:
    if (
        type(value) is not bytes
        or not MIN_KEY_BYTES <= len(value) <= MAX_KEY_BYTES
    ):
        raise InvalidAttestation("synthetic key shape")
    return value


def _body(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != BODY_FIELDS:
        raise InvalidAttestation("exact attestation body required")
    if value["schema"] != SCHEMA or type(value["schema"]) is not str:
        raise InvalidAttestation("schema")
    if type(value["key_id"]) is not str or not KEY_ID.fullmatch(value["key_id"]):
        raise InvalidAttestation("key identity")
    if type(value["tip_sha256"]) is not str or not HEX.fullmatch(value["tip_sha256"]):
        raise InvalidAttestation("chain tip")
    if type(value["nonce"]) is not str or not NONCE.fullmatch(value["nonce"]):
        raise InvalidAttestation("nonce")
    _utc(value["issued_at"])
    _utc(value["expires_at"])
    return value


def compute_mac(body: dict[str, object], secret: bytes) -> str:
    """Create a synthetic fixture MAC; never an actual grant/consent proof."""
    _valid_secret(secret)
    _body(body)
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("ascii")
    return hmac.new(secret, DOMAIN + canonical, hashlib.sha256).hexdigest()


def _check(raw: bytes, secret: bytes, now: datetime, expected_key_id: str) -> None:
    _valid_secret(secret)
    _now_utc(now)
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise InvalidAttestation("input bound")
    if (
        type(expected_key_id) is not str
        or not KEY_ID.fullmatch(expected_key_id)
    ):
        raise InvalidAttestation("expected key identity")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_keys,
            parse_constant=_nonfinite,
        )
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise InvalidAttestation("invalid JSON") from exc
    if type(value) is not dict or frozenset(value) != FIELDS:
        raise InvalidAttestation("unexpected attestation fields")
    body = {key: value[key] for key in BODY_FIELDS}
    _body(body)
    if not hmac.compare_digest(body["key_id"], expected_key_id):
        raise InvalidAttestation("wrong externally pinned key identity")
    mac = value["mac_sha256"]
    if type(mac) is not str or not HEX.fullmatch(mac):
        raise InvalidAttestation("MAC shape")
    issued = _utc(body["issued_at"])
    expires = _utc(body["expires_at"])
    if (
        issued > now + FUTURE_SKEW
        or expires <= now
        or expires <= issued
        or expires - issued > MAX_LIFETIME
    ):
        raise InvalidAttestation("time-window rejected")
    expected = compute_mac(body, secret)
    if not hmac.compare_digest(mac, expected):
        raise InvalidAttestation("HMAC mismatch")


def verify_attestation(
    raw: bytes, secret: bytes, now: datetime, expected_key_id: str
) -> dict[str, object]:
    """Return generic, non-authorizing status; never echo input or key."""
    status = "HOLD"
    try:
        _check(raw, secret, now, expected_key_id)
        status = "REVIEW_ONLY"
    except (
        InvalidAttestation, TypeError, ValueError, OverflowError, RecursionError,
    ):
        pass
    return {
        "status": status,
        "reason": "FICTIONAL_MAC_ONLY" if status == "REVIEW_ONLY" else "MAC_INVALID",
        **FALSE_FLAGS,
    }


def _read_fd_secret(fd: int) -> bytes:
    if type(fd) is not int or not 3 <= fd <= 255:
        raise InvalidAttestation("synthetic key fd")
    blocks: list[bytes] = []
    total = 0
    while total <= MAX_KEY_BYTES:
        block = os.read(fd, MAX_KEY_BYTES + 1 - total)
        if not block:
            break
        total += len(block)
        blocks.append(block)
    return _valid_secret(b"".join(blocks))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a fictional audit-tip MAC, NEVER consent or release"
    )
    parser.add_argument("--synthetic-only", action="store_true")
    parser.add_argument("--expected-key-id", required=True)
    parser.add_argument(
        "--key-fd", type=int, required=True,
        help="inherited dedicated FD (>=3), NOT an argv/env secret",
    )
    args = parser.parse_args(argv)
    raw = sys.stdin.buffer.read(MAX_BYTES + 1) if args.synthetic_only else b""
    try:
        secret = _read_fd_secret(args.key_fd) if args.synthetic_only else b""
    except (InvalidAttestation, OSError):
        secret = b""
    result = verify_attestation(
        raw, secret, datetime.now(timezone.utc), args.expected_key_id,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
