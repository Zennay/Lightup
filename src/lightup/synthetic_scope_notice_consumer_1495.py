"""Review-only decoder for an untrusted fictional scope notice JSON envelope.

Unwired and *incapable* of issuing grants, consent or execution permissions.
A successfully decoded preview is not authentic evidence of anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json

from .synthetic_scope_notice_1495 import ScopeProposal, _HOLD, render_scope_notice
from .synthetic_scope_notice_cli_1495 import _INVALID_MESSAGE, _utc

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



def _exact_original_fictional_report(
    notice: str, reviewed: int, elevated: bool,
) -> bool:
    """Check complete output against the original pure fictional producer.

    This is display consistency, NOT authenticated source, grant or consent.
    """
    lines = notice.split("\n")
    if not 1 <= reviewed <= 32 or len(lines) != 10 + reviewed:
        return False
    if lines[0] == _PREFIXES[0].rstrip("\n"):
        language = "en"
        timestamp_prefix = "Review timestamp (UTC): "
    elif lines[0] == _PREFIXES[1].rstrip("\n"):
        language = "nl"
        timestamp_prefix = "Beoordelingsmoment (UTC): "
    else:
        return False
    if not lines[3].startswith(timestamp_prefix):
        return False
    try:
        at = _utc(lines[3][len(timestamp_prefix):])
        entries = []
        for line in lines[6:6 + reviewed]:
            if not line.startswith("- "):
                return False
            parts = line[2:].split(" | ")
            if len(parts) != 5 or len(parts[2]) != 3:
                return False
            if parts[2][0] not in "12345" or parts[2][1:] != "/5":
                return False
            asset, capability, risk, start, end = parts
            entries.append(ScopeProposal(
                asset, capability, int(risk[0]), _utc(start), _utc(end),
            ))
        # Reject nonfictional assets, temporal invalidity, duplicates, risk
        # mismatch, reordered rows, injected banners, removed warning text.
        reference = render_scope_notice(
            tuple(entries), review_at=at, language=language,
        )
    except (ValueError, OverflowError, TypeError, UnicodeError):
        return False
    return (
        reference.status == "REVIEW_ONLY"
        and reference.text == notice
        and reference.reviewed == reviewed
        and reference.elevated_risk is elevated
        and reference.authorized is False
        and reference.consent_verified is False
        and reference.dispatch_allowed is False
        and reference.release_allowed is False
    )


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
        if not _exact_original_fictional_report(notice, reviewed, elevated):
            return None

    return FictionalNoticeView(
        status=status, notice=notice, reviewed=reviewed,
        elevated_risk=elevated,
    )
