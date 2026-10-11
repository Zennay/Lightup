"""Optional fail-closed shape check for a persisted post-render session snapshot.

This is an add-only reference helper for the authenticated checked-CSV owner.
It does NOT authenticate a token, authorize a tenant, install routes or protect
a response after bytes start transmitting. The caller must obtain the snapshot
from a fresh server-side durable DomainStore.session_context(token) lookup.
No existing production/default handler imports this helper.
"""
from __future__ import annotations

from ..domain import AccessContext


def is_canonical_postrender_session(
    snapshot: object, expected_context: AccessContext
) -> bool:
    """Accept only a canonical (unchanged AccessContext, nonempty CSRF) pair.

    Exact types intentionally avoid evaluating hostile list/tuple subclasses.
    The context comparison enforces same principal, role and tenant at the
    point of the second lookup; it is not proof of authorization by itself.
    """
    if type(expected_context) is not AccessContext:
        return False
    if type(snapshot) is not tuple or len(snapshot) != 2:
        return False
    current_context, csrf = snapshot
    return (
        type(current_context) is AccessContext
        and current_context == expected_context
        and type(csrf) is str
        and bool(csrf)
    )
