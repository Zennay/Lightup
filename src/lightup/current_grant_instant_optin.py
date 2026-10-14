"""Opt-in, non-authorizing current-grant instant admission reference (#890).

This standalone utility is NOT wired into the default DomainStore, executor,
web, grant issuance, queue, or production authorization. It only demonstrates
strict time-argument admission before delegating to the existing selector.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .domain import AccessContext, DomainStore
    from .engagements import AuthorizationGrant


def checked_current_grant_at(
    store: "DomainStore",
    context: "AccessContext",
    engagement_id: str,
    *,
    now: datetime | None = None,
) -> "AuthorizationGrant | None":
    """Select an existing grant only at an exact timezone-aware instant.

    None alone means an omitted instant, never a caller-supplied falsy value.
    This function does not issue, extend, approve, activate or authorize a
    grant; it is intentionally NOT a production security gate.
    """
    if now is None:
        instant = datetime.now(timezone.utc)
    else:
        if type(now) is not datetime:
            raise TypeError("grant evaluation instant must be an exact datetime")
        if now.tzinfo is None:
            raise ValueError("grant evaluation instant must be timezone-aware")
        # Exact datetime can still contain an opaque caller-supplied tzinfo.
        # Convert its exception to controlled pre-store denial; do not let
        # an invalid offset escape into the persisted authorization selector.
        try:
            offset = now.utcoffset()
        except Exception:
            raise ValueError("grant evaluation instant has invalid timezone offset") from None
        if offset is None:
            raise ValueError("grant evaluation instant must be timezone-aware")
        instant = now
    return store.get_current_grant(context, engagement_id, now=instant)
