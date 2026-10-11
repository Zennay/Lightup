"""Opt-in lexical admission for evidence identifiers.

This is NOT a tenant authorization or evidence-integrity decision. A valid
identifier must still pass authenticated ownership and source checks before
any persisted evidence is returned. Existing StateStore readers are unchanged.
"""
from __future__ import annotations

from uuid import UUID, RFC_4122


def canonical_evidence_id(value: object) -> str | None:
    """Accept only exact lowercase hyphenated RFC 4122 UUID version 4 text.

    Reject subclasses, aliases, controls and non-v4 IDs rather than silently
    normalizing caller input into a different database lookup identity.
    """
    if type(value) is not str or len(value) != 36:
        return None
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError):
        return None
    if parsed.version != 4 or parsed.variant != RFC_4122:
        return None
    if str(parsed) != value:
        return None
    return value
