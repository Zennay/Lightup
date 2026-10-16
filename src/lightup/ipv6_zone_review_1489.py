"""Strict, offline-only IPv6 authority zone diagnostic for issue #1489.

This pure helper is *not* installed in ScopePolicy, ActivationGate or a
network adapter. REVIEW_ONLY never means that an asset is authorized.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address, AddressValueError
from urllib.parse import urlsplit


class ZoneReviewStatus(str, Enum):
    HOLD = "HOLD"
    REVIEW_ONLY = "REVIEW_ONLY"


@dataclass(frozen=True)
class ZoneReview:
    status: ZoneReviewStatus
    reason: str
    execution_allowed: bool = False
    permit_allowed: bool = False
    dispatch_allowed: bool = False
    release_allowed: bool = False


_HOLD_FORMAT = ZoneReview(ZoneReviewStatus.HOLD, "noncanonical-or-invalid-authority")
_HOLD_ZONE = ZoneReview(ZoneReviewStatus.HOLD, "interface-zone-is-untrusted")
_REVIEW = ZoneReview(ZoneReviewStatus.REVIEW_ONLY, "canonical-unscoped-ipv6-shape-only")


def review_ipv6_authority_zone(value: object) -> ZoneReview:
    """Inspect a bounded, exact IPv6 authority *shape*, not permission.

    Only [canonical-lowercase-compressed-IPv6], optionally surrounded by
    http(s):// and a final /, is considered REVIEW_ONLY. Literal or escaped
    interface zone identifiers always HOLD, including on loopback/ULA/linklocal.
    No DNS, sockets, files, OS identity, tenant lookup, grants or execution.
    """
    if type(value) is not str or not (4 <= len(value) <= 256):
        return _HOLD_FORMAT
    if not value.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in value):
        return _HOLD_FORMAT
    if "://" in value:
        try:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in ("http", "https")
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.path not in ("", "/")
            ):
                return _HOLD_FORMAT
            authority = parsed.netloc
        except ValueError:
            return _HOLD_FORMAT
    else:
        authority = value
    if not authority.startswith("[") or not authority.endswith("]"):
        return _HOLD_FORMAT
    host = authority[1:-1]
    if "%" in host:
        return _HOLD_ZONE
    try:
        ip = IPv6Address(host)
    except (ValueError, AddressValueError):
        return _HOLD_FORMAT
    # Mapped IPv4 can have a different routing/scope interpretation from IPv6.
    # This review is IPv6-shape-only and must HOLD such aliases.
    if ip.ipv4_mapped is not None:
        return _HOLD_FORMAT
    if ip.scope_id is not None or str(ip) != host:
        return _HOLD_FORMAT
    return _REVIEW
