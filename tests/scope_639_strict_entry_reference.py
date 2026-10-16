"""Non-authorizing, opt-in review of persisted grant scope JSON for issue #639.

This module is deliberately not imported by any installed LightUp code.
A successful shape review is NOT a grant, permission, or release decision.
"""
from __future__ import annotations

import json
from typing import NamedTuple


class ReviewedScopeEntries(NamedTuple):
    assets: tuple[str, ...]
    excluded_assets: tuple[str, ...]
    allowed_capabilities: tuple[str, ...]


def review_scope_entries(
    *, assets_json: object, excluded_assets_json: object,
    allowed_capabilities_json: object,
) -> ReviewedScopeEntries | None:
    """Inspect *only* stored JSON entry shape; never mint execution authority.

    Returns an immutable plain-text snapshot or None, without normalization,
    fallback grants, network activity, or writes to caller-owned state.
    """
    parsed: list[tuple[str, ...]] = []
    for raw, required in (
        (assets_json, True),
        (excluded_assets_json, False),
        (allowed_capabilities_json, True),
    ):
        # Check exact types BEFORE invoking caller methods such as .strip or
        # __str__; even a str subclass is untrusted at this boundary.
        if type(raw) is not str:
            return None
        try:
            elements = json.loads(raw)
        except (ValueError, RecursionError):
            return None
        if type(elements) is not list or (required and not elements):
            return None
        for element in elements:
            if type(element) is not str or not element.strip():
                return None
        parsed.append(tuple(elements))

    return ReviewedScopeEntries(*parsed)
