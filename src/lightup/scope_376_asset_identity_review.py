"""Non-authorizing, offline shape review for grant asset identities (issue #376).

Not wired to DomainStore, execution policy, activation or tool handlers.
A REVIEW_ONLY result is never a grant, verified consent, or release approval.
"""
from __future__ import annotations

from dataclasses import dataclass

from .engagements import ScopeDefinition

_MAX_ENTRIES = 256
_MAX_ITEM_LENGTH = 2048


@dataclass(frozen=True, slots=True)
class AssetIdentityShapeReceipt:
    decision: str

    def __bool__(self) -> bool:
        """Never let a successful *shape* review act as a truthy permit."""
        return False

    def as_public_dict(self) -> dict[str, object]:
        """Do not disclose submitted identities or allow release/dispatch."""
        return {
            "decision": self.decision,
            "authorization_verified": False,
            "consent_verified": False,
            "grant_permitted": False,
            "dispatch_permitted": False,
            "merge_permitted": False,
            "release_permitted": False,
        }


def _canonical_tuple(values: object, *, allow_empty: bool) -> bool:
    if type(values) is not tuple:
        return False
    if (not allow_empty and not values) or len(values) > _MAX_ENTRIES:
        return False
    for value in values:
        # Type-check BEFORE strip/equality to avoid executing subclass methods.
        if type(value) is not str:
            return False
        if not value or len(value) > _MAX_ITEM_LENGTH or value != value.strip():
            return False
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            return False
    return True


def review_asset_identity_shape(scope: object) -> AssetIdentityShapeReceipt:
    """Review a *synthetic* ScopeDefinition's value shape without authorizing it.

    A conservative canonical-text subset; DNS, CIDR, consent, tenancy,
    expiry, revocation and capability authority are deliberately NOT checked.
    """
    # Reject subclass objects before reading any caller-controlled attributes.
    if type(scope) is not ScopeDefinition:
        return AssetIdentityShapeReceipt("HOLD")
    if not _canonical_tuple(scope.assets, allow_empty=False):
        return AssetIdentityShapeReceipt("HOLD")
    if not _canonical_tuple(scope.excluded_assets, allow_empty=True):
        return AssetIdentityShapeReceipt("HOLD")
    return AssetIdentityShapeReceipt("REVIEW_ONLY")
