"""Opt-in, fail-closed decoder for persisted request asset provenance (#877).

This read-only validation reference is deliberately NOT installed in the
default DomainStore reader, web/CLI, request approval or grant issuance.
It neither approves requests nor authorizes action on any returned asset.
"""
from __future__ import annotations

import json
from typing import Any


def checked_requested_assets_json(raw: Any) -> tuple[str, ...]:
    """Return an unchanged canonical nonempty string array, or deny.

    Caller is responsible for verifying tenant and request identity *before*
    using these values; successful parsing does not confer any authority.
    """
    if type(raw) is not str:
        raise ValueError("persisted request assets must be JSON text")
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ValueError("persisted request asset JSON invalid") from None
    if type(parsed) is not list or not parsed:
        raise ValueError("persisted request assets must be a nonempty JSON array")
    for asset in parsed:
        if type(asset) is not str or not asset.strip():
            raise ValueError("persisted request assets must be nonblank strings")
    # Do not mutate, strip, deduplicate, stringify or sort producer values:
    # admissibility and scope/permission are separate responsibilities.
    return tuple(parsed)
