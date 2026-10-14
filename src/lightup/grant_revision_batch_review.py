"""Atomic, opt-in, non-authorizing batch review of synthetic grant revisions."""
from __future__ import annotations

from dataclasses import dataclass

from .engagements import AuthorizationGrant
from .grant_revision_review import review_grant_revision


@dataclass(frozen=True)
class GrantRevisionBatchReview:
    verdict: str
    reason_code: str
    reviewed_count: int = 0
    narrowed_count: int = 0
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False


def _hold(reason: str) -> GrantRevisionBatchReview:
    # Atomic: do not report any partially eligible grant, even if a preceding
    # candidate passed syntactic review before a later one failed.
    return GrantRevisionBatchReview("HOLD", reason)


def review_grant_revision_batch(pairs: object) -> GrantRevisionBatchReview:
    """Review 1-32 untrusted pairs without granting any execution authority.

    A shared active asset in two proposed grants for distinct tenants is an
    ambiguous human-review assignment and causes atomic HOLD. This compares
    self-declared strings, not actual asset ownership or true entitlement.
    """
    if type(pairs) is not tuple or not (1 <= len(pairs) <= 32):
        return _hold("invalid_batch_shape")
    seen_ids: set[str] = set()
    per_tenant_assets: dict[str, set[str]] = {}
    narrowings = 0
    for pair in pairs:
        if type(pair) is not tuple or len(pair) != 2:
            return _hold("invalid_pair")
        old, new = pair
        if type(old) is not AuthorizationGrant or type(new) is not AuthorizationGrant:
            return _hold("invalid_grant_type")
        receipt = review_grant_revision(old, new)
        if receipt.verdict != "REVIEW_ONLY":
            return _hold("revision_held")
        if old.grant_id in seen_ids:
            return _hold("duplicate_grant_id")
        seen_ids.add(old.grant_id)
        narrowings += len(receipt.narrowed_fields)
        live_assets = set(new.scope.assets) - set(new.scope.excluded_assets)
        per_tenant_assets.setdefault(new.client_id, set()).update(live_assets)

    clients = sorted(per_tenant_assets)
    for i, left in enumerate(clients):
        for right in clients[i + 1:]:
            if per_tenant_assets[left] & per_tenant_assets[right]:
                return _hold("cross_tenant_asset_overlap")

    return GrantRevisionBatchReview(
        "REVIEW_ONLY", "batch_syntactically_nonwidening",
        reviewed_count=len(pairs), narrowed_count=narrowings,
    )
