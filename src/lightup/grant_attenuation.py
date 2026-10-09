"""Deny-only comparison of proposed reductions to an existing authorization grant.

This is an offline review primitive, NOT an authorization decision, trusted grant
lookup, issuance path, or execution permit. A positive comparison is never
sufficient to run a tool or contact a target.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .engagements import AuthorizationGrant, RiskLevel, ScopeDefinition

_MAX_ITEMS = 256
_MAX_TEXT = 512


@dataclass(frozen=True)
class GrantAttenuationDecision:
    nonexpanding: bool
    reasons: tuple[str, ...]

    @property
    def grants_execution_authority(self) -> bool:
        """A comparison cannot replace issuer proof or live revocation checks."""
        return False


def _identity(value: Any) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= _MAX_TEXT
        and value == value.strip()
        and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    )


def _names(values: Any, *, assets: bool) -> frozenset[str] | None:
    # The production ScopeDefinition asset check uses strip().lower().
    # Capability identity, in contrast, is case-sensitive and exact.
    if type(values) is not tuple or len(values) > _MAX_ITEMS:
        return None
    names: set[str] = set()
    for item in values:
        if not _identity(item):
            return None
        normalized = item.lower() if assets else item
        if normalized in names:
            return None
        names.add(normalized)
    return frozenset(names)


def _scope(value: Any) -> tuple[frozenset[str], frozenset[str], frozenset[str]] | None:
    if type(value) is not ScopeDefinition or type(value.max_risk) is not RiskLevel:
        return None
    assets = _names(value.assets, assets=True)
    exclusions = _names(value.excluded_assets, assets=True)
    capabilities = _names(value.allowed_capabilities, assets=False)
    if assets is None or exclusions is None or capabilities is None:
        return None
    if not assets:
        return None
    return assets, exclusions, capabilities


def _aware(value: Any) -> bool:
    # A caller-supplied tzinfo implementation could execute arbitrary callbacks
    # during date comparison. Admit only builtin fixed-offset timezone objects.
    if type(value) is not datetime or type(value.tzinfo) is not timezone:
        return False
    try:
        return value.tzinfo is not None and value.utcoffset() is not None
    except (TypeError, ValueError, OverflowError):
        return False


def compare_grant_attenuation(
    approved: AuthorizationGrant,
    proposal: AuthorizationGrant,
) -> GrantAttenuationDecision:
    """Compare two *untrusted snapshots* for privilege expansion, fail-closed.

    Even when nonexpanding=True, caller MUST obtain a fresh trusted approval
    record, recheck engagement/tenant/revocation, and enforce all real dispatch
    policy gates. Does not mutate either object or make network/DB calls.
    """
    if type(approved) is not AuthorizationGrant or type(proposal) is not AuthorizationGrant:
        return GrantAttenuationDecision(False, ("invalid_grant_type",))

    for grant in (approved, proposal):
        if not all(
            _identity(getattr(grant, field))
            for field in ("grant_id", "client_id", "engagement_id", "approved_by", "reference")
        ):
            return GrantAttenuationDecision(False, ("invalid_grant_identity",))
        if type(grant.recurring_retest_allowed) is not bool:
            return GrantAttenuationDecision(False, ("invalid_retest_flag",))
        if not _aware(grant.valid_from) or not _aware(grant.valid_until):
            return GrantAttenuationDecision(False, ("invalid_time_window",))
        try:
            if grant.valid_from >= grant.valid_until:
                return GrantAttenuationDecision(False, ("invalid_time_window",))
        except (TypeError, ValueError, OverflowError):
            return GrantAttenuationDecision(False, ("invalid_time_window",))

    original = _scope(approved.scope)
    changed = _scope(proposal.scope)
    if original is None or changed is None:
        return GrantAttenuationDecision(False, ("invalid_scope_shape",))

    reasons: list[str] = []
    for field in ("grant_id", "client_id", "engagement_id", "approved_by", "reference"):
        if getattr(approved, field) != getattr(proposal, field):
            reasons.append("identity_changed:" + field)

    try:
        if proposal.valid_from < approved.valid_from:
            reasons.append("window_start_expanded")
        if proposal.valid_until > approved.valid_until:
            reasons.append("window_end_expanded")
    except (TypeError, ValueError, OverflowError):
        reasons.append("invalid_time_window")

    if proposal.scope.max_risk > approved.scope.max_risk:
        reasons.append("risk_expanded")
    old_assets, old_excluded, old_caps = original
    new_assets, new_excluded, new_caps = changed

    if not new_assets.issubset(old_assets):
        reasons.append("assets_expanded")
    if not old_excluded.issubset(new_excluded):
        reasons.append("exclusions_removed")
    # An empty capability list means 'all capabilities' in ScopeDefinition.
    if old_caps and (not new_caps or not new_caps.issubset(old_caps)):
        reasons.append("capabilities_expanded")
    if not approved.recurring_retest_allowed and proposal.recurring_retest_allowed:
        reasons.append("retest_privilege_expanded")

    return GrantAttenuationDecision(not reasons, tuple(reasons))
