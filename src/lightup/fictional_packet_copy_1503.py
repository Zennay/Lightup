"""Offline, non-authorizing byte-copy check for *fictional* review packets.

This module is deliberately NOT imported by runtime authorization/dispatch code.
A digest is an untrusted copy-integrity hint, NOT consent, provenance or authority.
No filesystem, network, user-provided paths, logging or storage.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field

_SCHEMA = "lightup-fictional-copy-v1"
_KEYS = (
    "schema", "asset", "message", "capabilities",
    "authorized", "consent_verified", "dispatch_allowed", "release_allowed",
)
_ASSET = re.compile(r"[a-z][a-z0-9-]{0,31}\\.example\\.test", re.ASCII)
_CAPABILITIES = frozenset(("metadata_read", "report_preview", "scope_review"))
_MESSAGES = frozenset(("REVIEW_REQUIRED", "REVIEW_ON_HOLD"))
_MAX_PACKET_BYTES = 2048


@dataclass(frozen=True, slots=True)
class CopyReview:
    """All results deny authority. REVIEW_ONLY signals equality, not approval."""

    status: str
    sha256: str | None = None
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if type(self.status) is not str or self.status not in ("HOLD", "REVIEW_ONLY"):
            raise ValueError("invalid copy review status")
        if self.status == "HOLD":
            if self.sha256 is not None:
                raise ValueError("HOLD may not expose a fingerprint")
        elif (
            type(self.sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.sha256, re.ASCII) is None
        ):
            raise ValueError("review fingerprint is not canonical")


def _reject_duplicates(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-JSON numeric constant")


def _is_canonical_fictional_packet(raw: bytes) -> bool:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_PACKET_BYTES:
        return False
    try:
        decoded = raw.decode("ascii")
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
        if type(parsed) is not dict or tuple(parsed) != _KEYS:
            return False
        if parsed["schema"] != _SCHEMA or type(parsed["schema"]) is not str:
            return False
        asset = parsed["asset"]
        if type(asset) is not str or _ASSET.fullmatch(asset) is None:
            return False
        if type(parsed["message"]) is not str or parsed["message"] not in _MESSAGES:
            return False
        capabilities = parsed["capabilities"]
        if (
            type(capabilities) is not list
            or not 1 <= len(capabilities) <= len(_CAPABILITIES)
            or any(type(item) is not str or item not in _CAPABILITIES for item in capabilities)
            or capabilities != sorted(set(capabilities))
        ):
            return False
        if any(parsed[key] is not False for key in _KEYS[-4:]):
            return False
        canonical = json.dumps(
            parsed, ensure_ascii=True, separators=(",", ":"), sort_keys=False,
            allow_nan=False,
        ).encode("ascii")
        return hmac.compare_digest(raw, canonical)
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        return False


def compare_fictional_packet_copies(original: bytes, received: bytes) -> CopyReview:
    """Only identical strictly canonical fictional ASCII bytes get REVIEW_ONLY.

    If either copy is invalid, modified, ambiguous or different, emit a generic
    HOLD with zero source-value echo and no partial digest. The caller supplies
    BOTH copies: this function cannot authenticate their origin or their author.
    """
    if not _is_canonical_fictional_packet(original):
        return CopyReview("HOLD")
    if not _is_canonical_fictional_packet(received):
        return CopyReview("HOLD")
    if not hmac.compare_digest(original, received):
        return CopyReview("HOLD")
    return CopyReview("REVIEW_ONLY", hashlib.sha256(original).hexdigest())
