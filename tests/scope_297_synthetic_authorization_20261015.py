"""Synthetic-only #297 authorizations compatible with current and owner-bound models.

This is test fixture data, NOT a grant issuer or a production import. All
listed targets are reserved documentation ranges or the fictional .test TLD.
"""
from __future__ import annotations

from datetime import datetime
from lightup.models import Authorization

FICTIONAL_ASSETS: tuple[str, ...] = (
    "security.example.test",
    "198.51.100.42",
    "198.51.100.43",
    "198.51.100.44",
    "203.0.113.45",
    "2001:db8::42",
)


def fake_authorization(
    *,
    owner: str,
    reference: str,
    valid_from: datetime,
    valid_until: datetime,
) -> Authorization:
    """Build a test-only grant without granting anything in runtime.

    main's legacy Authorization has no asset-binding field. The independent
    source-owner PR #100 adds exact per-asset grants. A normal fake test must
    state exact fictional assets there; otherwise positive scope checks
    spuriously fail even though owner binding is doing its job.
    """
    params = {
        "owner": owner,
        "reference": reference,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    # Check the *installed* model, not GitHub-branch identity or user input.
    if "assets" in getattr(Authorization, "__dataclass_fields__", {}):
        params["assets"] = FICTIONAL_ASSETS
    return Authorization(**params)
