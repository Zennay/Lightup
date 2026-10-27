"""Unwired, non-authorizing legacy permit/decision consistency review (#1491).

Both inputs and the claimed reference are caller-controlled. REVIEW_ONLY means
only that their *synthetic shapes* cohere, never that either has trusted origin.
No clock, network, storage, handler, scanner, or grant interfaces are used.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
import re

from .activation import ActivationMode, ExecutionPermit
from .scope import ScopeDecision, ScopeReason


@dataclass(frozen=True)
class PermitDecisionReview:
    status: str
    reason: str
    authorized: bool = False
    consent_verified: bool = False
    dispatch_allowed: bool = False
    release_allowed: bool = False


def _hold(reason: str) -> PermitDecisionReview:
    return PermitDecisionReview("HOLD", reason)


def _canonical_host(value: object, reason: ScopeReason) -> bool:
    if type(value) is not str or not 1 <= len(value) <= 253:
        return False
    if value != value.strip() or value != value.lower():
        return False
    if not value.isascii() or any(c in value for c in "%/@\\?#[] \t\r\n"):
        return False
    if reason is ScopeReason.LOOPBACK and value == "localhost":
        return True
    try:
        addr = ip_address(value)
    except ValueError:
        return False
    # This strict reviewer deliberately does not infer lab consent from
    # ipaddress.is_private (which includes special-use/non-routable blocks).
    if str(addr) != value or "%" in value:
        return False
    if reason is ScopeReason.LOOPBACK:
        return addr.is_loopback
    if reason is ScopeReason.PRIVATE_LAB:
        if isinstance(addr, IPv4Address):
            return any(addr in block for block in (
                _V4_PRIVATE_10, _V4_PRIVATE_172, _V4_PRIVATE_192
            ))
        return isinstance(addr, IPv6Address) and addr in _V6_ULA
    return False


# Standard-library constant CIDR construction is pure and uses no DNS.
from ipaddress import ip_network
_V4_PRIVATE_10 = ip_network("10.0.0.0/8")
_V4_PRIVATE_172 = ip_network("172.16.0.0/12")
_V4_PRIVATE_192 = ip_network("192.168.0.0/16")
_V6_ULA = ip_network("fc00::/7")


def review_permit_decision(
    permit: object,
    decision: object,
    claimed_lab_reference: object,
) -> PermitDecisionReview:
    """Review fictional evidence only; never returns execution authorization."""
    if type(permit) is not ExecutionPermit or type(decision) is not ScopeDecision:
        return _hold("noncanonical_record_type")
    # Even an exact frozen dataclass can have missing/extra instance fields.
    if vars(permit).keys() != {
        "permit_id", "target", "capability_id", "mode",
        "activation_reference", "issued_at",
    } or vars(decision).keys() != {"allowed", "normalized_host", "reason"}:
        return _hold("invalid_record_fields")
    if type(decision.allowed) is not bool or not decision.allowed:
        return _hold("denied_or_nonboolean_decision")
    if type(decision.reason) is not ScopeReason:
        return _hold("noncanonical_reason")
    if type(permit.mode) is not ActivationMode or permit.mode is not ActivationMode.LAB_ONLY:
        # AUTHORIZED needs independent operator/client/asset/consent/revocation.
        return _hold("mode_requires_trusted_provenance")
    if decision.reason not in (ScopeReason.LOOPBACK, ScopeReason.PRIVATE_LAB):
        return _hold("reason_outside_lab")
    if not _canonical_host(decision.normalized_host, decision.reason):
        return _hold("invalid_target_identity")
    if type(permit.target) is not str or permit.target != decision.normalized_host:
        return _hold("target_decision_mismatch")
    if type(permit.permit_id) is not str or not re.fullmatch(
        r"[A-Za-z0-9_-]{24,64}", permit.permit_id, flags=re.ASCII
    ):
        return _hold("invalid_permit_identifier")
    if type(permit.capability_id) is not str or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{1,63}", permit.capability_id, flags=re.ASCII
    ):
        return _hold("invalid_capability_identifier")
    if type(claimed_lab_reference) is not str or not re.fullmatch(
        r"LAB-[A-Za-z0-9][A-Za-z0-9._:-]{3,120}",
        claimed_lab_reference, flags=re.ASCII
    ):
        return _hold("invalid_claimed_lab_reference")
    if type(permit.activation_reference) is not str or (
        permit.activation_reference != claimed_lab_reference
    ):
        return _hold("lab_reference_mismatch")
    if type(permit.issued_at) is not datetime or (
        permit.issued_at.tzinfo is not timezone.utc
    ):
        return _hold("invalid_issuance_timestamp")
    # A UTC instant's freshness cannot be proven without an authenticated clock.
    # Likewise, two matching records are NOT a trusted decision/permit binding.
    return PermitDecisionReview("REVIEW_ONLY", "synthetic_claims_cohere")
