"""Opt-in offline review of a proposed revision to an existing authorization grant.

This is a syntactic narrowing check, not an authorization decision. It makes
no network, database, or executor calls and is not installed in the dispatch path.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from re import fullmatch

from .engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


@dataclass(frozen=True)
class GrantRevisionReview:
    verdict: str
    reason_code: str
    narrowed_fields: tuple[str, ...] = ()
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False


def _hold(reason: str) -> GrantRevisionReview:
    return GrantRevisionReview("HOLD", reason)


def _tokens(values: object, *, allow_empty: bool = False) -> frozenset[str] | None:
    if type(values) is not tuple or len(values) > 128:
        return None
    if not values and not allow_empty:
        return None
    result: set[str] = set()
    for value in values:
        # Only strict ASCII identity is handled here. Aliases need a separate
        # trusted canonicalization and approval process, never DNS resolution.
        if (
            type(value) is not str
            or len(value) < 1
            or len(value) > 253
            or value != value.lower()
            or fullmatch(r"[a-z0-9][a-z0-9._:/-]*", value, flags=0) is None
            or value.endswith(".")
            or ".." in value
            or value in result
        ):
            return None
        # Numeric host aliases (127.1, zero-padded IPv4, noncanonical IPv6)
        # must not disguise overlap in an operator's cross-tenant batch.
        # Never perform DNS or external resolution.
        if "/" in value:
            try:
                if str(ip_network(value, strict=True)) != value:
                    return None
            except ValueError:
                return None
        elif ":" in value or fullmatch(r"[0-9.]+", value) is not None:
            try:
                if str(ip_address(value)) != value:
                    return None
            except ValueError:
                return None
        result.add(value)
    return frozenset(result)


def _identity(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", value, flags=0) is not None
    )


def _utc_datetime(value: object) -> bool:
    if type(value) is not datetime or value.tzinfo is None:
        return False
    try:
        return value.utcoffset() == timedelta(0)
    except (OverflowError, TypeError, ValueError):
        return False


def _scope_shape(scope: object) -> tuple[frozenset[str], frozenset[str], frozenset[str]] | None:
    if type(scope) is not ScopeDefinition or type(scope.max_risk) is not RiskLevel:
        return None
    assets = _tokens(scope.assets)
    exclusions = _tokens(scope.excluded_assets, allow_empty=True)
    capabilities = _tokens(scope.allowed_capabilities, allow_empty=True)
    if assets is None or exclusions is None or capabilities is None:
        return None
    if exclusions - assets:
        return None
    return assets, exclusions, capabilities


def review_grant_revision(current: object, proposed: object) -> GrantRevisionReview:
    """Review self-declared grant fields; REVIEW_ONLY is *never* permission.

    HOLD on ambiguity, identity change, risk/window expansion, newly authorized
    assets, removed exclusions or wider capabilities/retest authority. No
    grant issuance or execution is performed under any verdict.
    """
    if type(current) is not AuthorizationGrant or type(proposed) is not AuthorizationGrant:
        return _hold("invalid_grant_type")
    keys = ("grant_id", "client_id", "engagement_id", "approved_by", "reference")
    if any(not _identity(getattr(g, key)) for g in (current, proposed) for key in keys):
        return _hold("invalid_identity")
    if any(getattr(current, key) != getattr(proposed, key) for key in keys):
        return _hold("identity_changed")

    old_scope = _scope_shape(current.scope)
    new_scope = _scope_shape(proposed.scope)
    if old_scope is None or new_scope is None:
        return _hold("invalid_scope")
    if (
        type(current.recurring_retest_allowed) is not bool
        or type(proposed.recurring_retest_allowed) is not bool
    ):
        return _hold("invalid_retest_authority")
    if not all(
        _utc_datetime(value)
        for value in (current.valid_from, current.valid_until, proposed.valid_from, proposed.valid_until)
    ):
        return _hold("invalid_utc_window")
    if current.valid_from > current.valid_until or proposed.valid_from > proposed.valid_until:
        return _hold("invalid_window_order")

    old_assets, old_exclusions, old_caps = old_scope
    new_assets, new_exclusions, new_caps = new_scope
    if not new_assets <= old_assets:
        return _hold("asset_expansion")
    # Retain exclusions for assets that remain; deleting an asset itself is safe.
    if not (old_exclusions & new_assets) <= new_exclusions:
        return _hold("exclusion_removed")
    # Empty capabilities in the existing ScopeDefinition mean unrestricted,
    # not "deny all": never treat [] as a safe narrowing target.
    if old_caps and (not new_caps or not new_caps <= old_caps):
        return _hold("capability_expansion")
    if not new_caps:
        return _hold("unrestricted_proposed_capabilities")
    if proposed.scope.max_risk > current.scope.max_risk:
        return _hold("risk_expansion")
    if proposed.scope.max_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY:
        return _hold("destructive_risk_not_reviewable")
    if proposed.valid_from < current.valid_from or proposed.valid_until > current.valid_until:
        return _hold("window_expansion")
    if proposed.recurring_retest_allowed and not current.recurring_retest_allowed:
        return _hold("retest_authority_expansion")

    changes: list[str] = []
    if new_assets != old_assets:
        changes.append("assets")
    if new_exclusions != old_exclusions:
        changes.append("excluded_assets")
    if new_caps != old_caps:
        changes.append("capabilities")
    if proposed.scope.max_risk < current.scope.max_risk:
        changes.append("risk")
    if proposed.valid_from > current.valid_from or proposed.valid_until < current.valid_until:
        changes.append("window")
    if current.recurring_retest_allowed and not proposed.recurring_retest_allowed:
        changes.append("recurring_retest")
    return GrantRevisionReview("REVIEW_ONLY", "syntactically_nonwidening", tuple(changes))
