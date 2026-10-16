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

    def __post_init__(self) -> None:
        # Prevent counterfeit APPROVED/PASS or coercive status objects.
        if type(self.decision) is not str or self.decision not in ("HOLD", "REVIEW_ONLY"):
            raise ValueError("invalid review decision")

    def __bool__(self) -> bool:
        """Never let a successful *shape* review act as a truthy permit."""
        return False

    def as_public_dict(self) -> dict[str, object]:
        """Fail closed even if a frozen receipt was modified by object.__setattr__.

        Python frozen/slots are not a security boundary. Serialized data is
        still NEVER an authenticated grant or an authorization to dispatch.
        """
        try:
            status = object.__getattribute__(self, "decision")
        except AttributeError:
            status = None
        safe_status = (status if type(status) is str
                       and status in ("HOLD", "REVIEW_ONLY") else "HOLD")
        return {
            "decision": safe_status,
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
        # Embedded and non-ASCII whitespace is never a canonical asset ID.
        # Exact built-in str only: no attacker-supplied __str__/comparison.
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
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
    # A frozen dataclass is not tamper-proof: object.__delattr__ can remove
    # exclusions and ordinary attribute lookup would silently use its class
    # default (). Require the exact instance field envelope before accesses.
    try:
        fields = object.__getattribute__(scope, "__dict__")
    except (AttributeError, TypeError):
        return AssetIdentityShapeReceipt("HOLD")
    if type(fields) is not dict or len(fields) != 4:
        return AssetIdentityShapeReceipt("HOLD")
    # Take a bounded snapshot of the exact built-in dict before validating.
    # A caller can bypass frozen dataclass assignment and change its __dict__.
    # Never interleave key checks on one version with value reads from another.
    snapshot = fields.copy()
    if len(snapshot) != 4 or any(type(key) is not str for key in snapshot):
        return AssetIdentityShapeReceipt("HOLD")
    if set(snapshot) != {"assets", "excluded_assets", "max_risk",
                         "allowed_capabilities"}:
        return AssetIdentityShapeReceipt("HOLD")
    assets = snapshot["assets"]
    exclusions = snapshot["excluded_assets"]
    if not _canonical_tuple(assets, allow_empty=False):
        return AssetIdentityShapeReceipt("HOLD")
    if not _canonical_tuple(exclusions, allow_empty=True):
        return AssetIdentityShapeReceipt("HOLD")
    # Values are now confirmed exact native strings. Repeated identities, or
    # exact allow/exclude contradictions, need owner review rather than a
    # guessed precedence. Do NOT casefold/normalize or create authorization.
    allowed = set(assets)
    excluded = set(exclusions)
    if (len(allowed) != len(assets)
            or len(excluded) != len(exclusions)
            or not allowed.isdisjoint(excluded)):
        return AssetIdentityShapeReceipt("HOLD")
    return AssetIdentityShapeReceipt("REVIEW_ONLY")
