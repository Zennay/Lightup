"""Review-only decoder for an untrusted fictional scope notice JSON envelope.

Unwired and *incapable* of issuing grants, consent or execution permissions.
A successfully decoded preview is not authentic evidence of anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json

from .synthetic_scope_notice_1495 import _HOLD
from .synthetic_scope_notice_cli_1495 import _INVALID_MESSAGE

_MAX_ENVELOPE_BYTES = 65536
_ALLOWED_KEYS = frozenset((
    "status", "notice", "reviewed", "elevated_risk",
    "authorized", "consent_verified", "dispatch_allowed", "release_allowed",
))
_FALSE_KEYS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
_PREFIXES = (
    "NOT AUTHORIZED — SYNTHETIC SCOPE REVIEW ONLY\n",
    "NOT AUTHORIZED — NIET GEAUTORISEERD | UITSLUITEND FICTIEVE SCOPE\n",
)


@dataclass(frozen=True, slots=True)
class FictionalNoticeView:
    """A display-only receipt; all four authority flags are ALWAYS false."""

    status: str
    notice: str
    reviewed: int
    elevated_risk: bool
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def _unique_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON keys are ambiguous")
        result[name] = value
    return result


def _deny_nonfinite(_: str) -> object:
    raise ValueError("nonfinite")


def decode_fictional_notice_for_display(raw: bytes) -> FictionalNoticeView | None:
    """Return a display-only value or None for ANY malformed/untrusted input.

    Never fall back to a positive status, normalize a field, perform I/O or
    convert an untrusted envelope into verified authorization.
    """
    if type(raw) is not bytes or not (1 <= len(raw) <= _MAX_ENVELOPE_BYTES):
        return None
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_json_keys,
            parse_constant=_deny_nonfinite,
        )
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
        return None
    if type(payload) is not dict or frozenset(payload) != _ALLOWED_KEYS:
        return None
    if not all(payload.get(key) is False for key in _FALSE_KEYS):
        return None

    status = payload["status"]
    notice = payload["notice"]
    reviewed = payload["reviewed"]
    elevated = payload["elevated_risk"]
    if type(status) is not str or status not in ("HOLD", "REVIEW_ONLY"):
        return None
    if type(notice) is not str or not (15 <= len(notice) <= 8192):
        return None
    if type(reviewed) is not int or not (0 <= reviewed <= 32):
        return None
    if type(elevated) is not bool:
        return None
    if any(ord(char) < 32 and char != "\n" for char in notice):
        return None
    if any(char in notice for char in ("\u202e", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069")):
        return None
    try:
        notice.encode("utf-8")
    except UnicodeError:
        return None

    if status == "HOLD":
        # Known HOLD text comes from the synthetic producer only. No
        # user-controlled fields or raw assets may be echoed after rejection.
        if reviewed != 0 or elevated or notice not in (_HOLD, _INVALID_MESSAGE):
            return None
    else:
        if reviewed == 0 or not notice.startswith(_PREFIXES):
            return None
        if notice.startswith(_PREFIXES[0]):
            if f"Fictional proposal count: {reviewed}\n" not in notice:
                return None
            if "No client consent, operator identity" not in notice:
                return None
            if "This is NOT a grant, consent record" not in notice:
                return None
        else:
            if f"Aantal fictieve voorstellen: {reviewed}\n" not in notice:
                return None
            if "Geen klanttoestemming, operatoridentiteit" not in notice:
                return None
            if "Dit is GEEN toestemming, grant" not in notice:
                return None
        if "NOT AUTHORIZED" not in notice:
            return None

    return FictionalNoticeView(
        status=status, notice=notice, reviewed=reviewed,
        elevated_risk=elevated,
    )
