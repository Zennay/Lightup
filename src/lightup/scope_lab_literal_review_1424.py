"""Opt-in offline IP-literal *review* for lab planning (#1424).

NOT an authorization policy, an ExecutionPermit, a grant, or an installed
runtime guard. Never connect this module to target-active dispatch.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Literal


_V4_LAB = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
)
_V4_LOOPBACK = ip_network("127.0.0.0/8")
_V6_ULA = ip_network("fc00::/7")
_V6_LOOPBACK = ip_address("::1")


@dataclass(frozen=True, slots=True)
class LabLiteralReview:
    """Immutable non-authorizing result, never a scope/permit decision."""

    status: Literal["HOLD", "REVIEW_ONLY"] = "HOLD"
    classification: Literal["UNTRUSTED", "LOOPBACK", "PRIVATE_USE"] = "UNTRUSTED"
    authorization_verified: Literal[False] = False
    permit_issued: Literal[False] = False
    execution_enabled: Literal[False] = False
    merge_approved: Literal[False] = False
    release_approved: Literal[False] = False

    def __post_init__(self) -> None:
        # Dataclass annotations are not runtime checks. Refuse constructed
        # authority-looking receipts before any caller can observe them.
        if type(self.status) is not str or self.status not in ("HOLD", "REVIEW_ONLY"):
            raise ValueError("invalid review status")
        if (type(self.classification) is not str or
                self.classification not in ("UNTRUSTED", "LOOPBACK", "PRIVATE_USE")):
            raise ValueError("invalid review classification")
        if (self.status == "HOLD") != (self.classification == "UNTRUSTED"):
            raise ValueError("inconsistent review-only classification")
        for flag in (
            self.authorization_verified, self.permit_issued,
            self.execution_enabled, self.merge_approved, self.release_approved,
        ):
            if flag is not False:
                raise ValueError("lab literal review cannot confer authority")


_HOLD = LabLiteralReview()


def review_lab_literal(value: object) -> LabLiteralReview:
    """Classify an exact canonical address *only for offline review*.

    This is intentionally not ScopePolicy.decide: no tenant, grant,
    risk, execution, or target decision exists in this function.

    Refuse all unknown types/representations before trying parse helpers.
    Never trust ipaddress.is_private or is_global for lab membership.
    """
    if type(value) is not str or not value or len(value) > 45:
        return _HOLD
    try:
        address = ip_address(value)
    except ValueError:
        return _HOLD
    # ip_address accepts some valid but noncanonical variants. Conservative
    # review avoids independent parse interpretations at API boundaries.
    if value != str(address):
        return _HOLD

    if type(address) is IPv4Address:
        if address in _V4_LOOPBACK:
            return LabLiteralReview("REVIEW_ONLY", "LOOPBACK")
        if any(address in network for network in _V4_LAB):
            return LabLiteralReview("REVIEW_ONLY", "PRIVATE_USE")
        return _HOLD

    if type(address) is IPv6Address:
        if address.scope_id is not None or address.ipv4_mapped is not None:
            return _HOLD
        if address == _V6_LOOPBACK:
            return LabLiteralReview("REVIEW_ONLY", "LOOPBACK")
        if address in _V6_ULA:
            return LabLiteralReview("REVIEW_ONLY", "PRIVATE_USE")
    return _HOLD
