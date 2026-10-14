"""Isolated opt-in issuance datetime snapshot for #647 (not runtime wiring).

Source owner PR #554 remains responsible for production admission. This
pure helper does not issue a grant, check client consent, touch SQLite,
resolve a target, or authorize any tool. It returns only exact builtin UTC
datetime objects that cannot override comparisons/isoformat at persistence.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import NamedTuple


class WindowRejected(ValueError):
    """Temporal input cannot be safely snapshotted before issuance."""


class CanonicalIssueWindow(NamedTuple):
    starts_at_utc: datetime
    expires_at_utc: datetime


def snapshot_grant_issuance_window(
    valid_from: object,
    valid_until: object,
) -> CanonicalIssueWindow:
    """Snapshot a syntactically valid UTC window; NEVER issue authorization.

    Require exact builtin aware datetime with exact builtin fixed-offset
    timezone on *both* ends. Normalize to immutable exact builtin UTC values.
    Reject timezone implementations/subclasses before ANY virtual method call.
    An empty or reversed window is rejected. No implicit clock is consulted.

    This is only a non-authorizing utility for source-owner evaluation.
    It does not prove a human signed the scope, current revocation, tenant
    ownership, capability or asset reachability.
    """
    if type(valid_from) is not datetime or type(valid_until) is not datetime:
        raise WindowRejected("noncanonical datetime")
    if (type(valid_from.tzinfo) is not timezone or
            type(valid_until.tzinfo) is not timezone):
        raise WindowRejected("noncanonical timezone")
    try:
        start = valid_from.astimezone(timezone.utc)
        until = valid_until.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise WindowRejected("invalid timezone conversion") from None
    if type(start) is not datetime or type(until) is not datetime:
        raise WindowRejected("noncanonical snapshot")
    if until <= start:
        raise WindowRejected("invalid window")
    return CanonicalIssueWindow(start, until)
