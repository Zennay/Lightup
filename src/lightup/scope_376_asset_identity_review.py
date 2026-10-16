"""Non-authorizing, offline shape review for grant asset identities (issue #376).

Not wired to DomainStore, execution policy, activation or tool handlers.
A REVIEW_ONLY result is never a grant, verified consent, or release approval.
"""
from __future__ import annotations

from dataclasses import dataclass
from unicodedata import category

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
        # Exact built-in strings only. Unicode C* includes controls, format
        # characters (bidi/zero-width), surrogates, private-use, unassigned.
        # Do not silently normalize or reinterpret identity/alias authority.
        if any(char.isspace() or category(char).startswith("C") for char in value):
            return False
    return True


def _canonical_asset_snapshot(scope: object) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Take ONE shape-reviewed immutable asset/exclusion snapshot, or deny.

    Internal offline value contract. This snapshot neither grants authority nor
    validates risk, capabilities, provenance, consent or revocation. Never
    reuse the mutable original ScopeDefinition object after reviewing it.
    """
    if type(scope) is not ScopeDefinition:
        return None
    try:
        fields = object.__getattribute__(scope, "__dict__")
    except (AttributeError, TypeError):
        return None
    if type(fields) is not dict or len(fields) != 4:
        return None
    snapshot = fields.copy()
    if len(snapshot) != 4 or any(type(key) is not str for key in snapshot):
        return None
    if set(snapshot) != {"assets", "excluded_assets", "max_risk",
                         "allowed_capabilities"}:
        return None
    assets = snapshot["assets"]
    exclusions = snapshot["excluded_assets"]
    if not _canonical_tuple(assets, allow_empty=False):
        return None
    if not _canonical_tuple(exclusions, allow_empty=True):
        return None
    # Both are now exact native tuples of exact native str elements.
    allowed = set(assets)
    excluded = set(exclusions)
    if (len(allowed) != len(assets)
            or len(excluded) != len(exclusions)
            or not allowed.isdisjoint(excluded)):
        return None
    return assets, exclusions


def review_asset_identity_shape(scope: object) -> AssetIdentityShapeReceipt:
    """Inspect asset *shape* only: never treat REVIEW_ONLY as authorization.

    Risk/capability/consent, DNS/IP, tenure, expiry, tenancy and revocation
    remain independent owner-controlled requirements.
    """
    result = _canonical_asset_snapshot(scope)
    return AssetIdentityShapeReceipt("REVIEW_ONLY" if result is not None else "HOLD")
