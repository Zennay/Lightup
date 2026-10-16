"""Strict persisted scope entry-shape review for scope issue #639.

This pure helper is deliberately NOT called from installed admission paths.
It cannot construct a grant, approve consent, perform network I/O, or decide
whether an asset/capability is authorized. A valid shape is never a GO.
See #554 for ownership of the actual durable execution resolver.
"""
from __future__ import annotations

import json
from typing import NamedTuple

# Conservative draft ceilings, applied before expensive JSON parsing. The
# production resolver owner must separately approve these policy limits.
MAX_SCOPE_JSON_CHARS = 65_536
MAX_SCOPE_ENTRIES = 256
MAX_SCOPE_ENTRY_CHARS = 2_048


class PersistedScopeEntries(NamedTuple):
    """Immutable literal strings only; **not** an AuthorizationGrant."""

    assets: tuple[str, ...]
    excluded_assets: tuple[str, ...]
    allowed_capabilities: tuple[str, ...]


def review_persisted_scope_entries(
    *,
    assets_json: object,
    excluded_assets_json: object,
    allowed_capabilities_json: object,
) -> PersistedScopeEntries | None:
    """Return canonical nested-JSON shape only, never executable authority.

    For each SQLite JSON column, require an exact built-in str encoding a JSON
    list whose elements are all exact built-in nonblank strings. Nonempty
    assets/capabilities are mandatory; empty exclusions are permitted.
    No input normalization, filtering, coercion, writes or capability lookup.
    Raw persisted rows remain for forensic review after denial.
    Enforce explicit resource limits before parsing and before tuple creation.
    """
    arrays: list[tuple[str, ...]] = []
    for raw, required in (
        (assets_json, True),
        (excluded_assets_json, False),
        (allowed_capabilities_json, True),
    ):
        # Reject str subclasses and other spoofed input *before* any method
        # calls on user-supplied objects. Untrusted __str__ is never invoked.
        if type(raw) is not str or len(raw) > MAX_SCOPE_JSON_CHARS:
            return None
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError, RecursionError):
            return None
        if (type(decoded) is not list or len(decoded) > MAX_SCOPE_ENTRIES
                or (required and not decoded)):
            return None
        for entry in decoded:
            if (type(entry) is not str or len(entry) > MAX_SCOPE_ENTRY_CHARS
                    or not entry.strip()):
                return None
        arrays.append(tuple(decoded))
    return PersistedScopeEntries(*arrays)
