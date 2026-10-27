"""Strict, fail-closed handling of authorization time-window instants.

Authorization windows are a security boundary. Their bounds must therefore be
exact builtin, timezone-aware ``datetime`` objects. Subclasses can override
comparison or serialization (so the value that is checked differs from the
value that is persisted), and falsy placeholders such as ``0``, ``False`` or
``""`` must never be read as "unbounded".
"""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

_TRUSTED_TZINFO = (timezone, ZoneInfo)


def canonical_instant(value: object) -> datetime | None:
    """Return ``value`` as an exact builtin UTC datetime, or ``None`` if unsafe."""
    if type(value) is not datetime:
        return None
    if type(value.tzinfo) not in _TRUSTED_TZINFO:
        return None
    try:
        if value.utcoffset() is None:
            return None
        converted = value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None
    if type(converted) is not datetime:
        return None
    return converted


def require_instant(value: object, label: str) -> datetime:
    """Like :func:`canonical_instant` but raise ``ValueError`` when unsafe."""
    instant = canonical_instant(value)
    if instant is None:
        raise ValueError(f"{label} must be an exact timezone-aware datetime")
    return instant


def evaluation_instant(now: datetime | None) -> datetime:
    """Resolve the instant an authorization window is evaluated at."""
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime) and now.tzinfo is None:
        raise ValueError("authorization time must be timezone-aware")
    return require_instant(now, "evaluation time")
