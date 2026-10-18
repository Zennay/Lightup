"""Fail-closed approved-request/scope checks for durable LightUp grant issuance.

No target I/O, scan, execution permission, consent signature or grant creation.
Only the domain layer can use this as one gate in its own durable transaction.
"""
from __future__ import annotations

from datetime import datetime
from ipaddress import ip_network
import json
import re


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _asset(raw: object):
    if type(raw) is not str or not raw or raw.strip() != raw or len(raw) > 253:
        raise ValueError("asset must be a single canonical host, IP or CIDR literal")
    if any(ord(char) < 33 or ord(char) > 126 for char in raw):
        raise ValueError("asset has non-ASCII, controls or whitespace")
    if "%" in raw or "@" in raw or "://" in raw or "?" in raw or "#" in raw:
        raise ValueError("URL, encoded and ambiguous asset identities are not accepted")
    try:
        value = ip_network(raw, strict=True)
    except ValueError:
        value = None
    if value is not None:
        return ("network", value)
    # Anything syntactically IP-/CIDR-like must not fall back to hostname.
    if "/" in raw or ":" in raw or re.fullmatch(r"[0-9.]+", raw):
        raise ValueError("invalid or noncanonical IP/CIDR")
    lowered = raw.lower()
    if (
        lowered.endswith(".") or ".." in lowered or "." not in lowered
        or not all(_HOST_LABEL.fullmatch(piece) for piece in lowered.split("."))
    ):
        raise ValueError("noncanonical hostname")
    return ("host", lowered)


def assets_within_approved_request(requested_json: str, granted_assets: tuple[str, ...]) -> bool:
    """Conservative subset: DNS is literal; subnets only cover same-family IPs.

    No wildcard, DNS lookup, Unicode alias, URL, permissive CIDR rounding,
    zone ID or hostname-to-IP expansion is ever implicit.
    """
    if type(requested_json) is not str or type(granted_assets) is not tuple:
        return False
    try:
        requested = json.loads(requested_json)
        if type(requested) is not list or not requested or len(requested) > 80:
            return False
        if not granted_assets or len(granted_assets) > 80:
            return False
        bases = [_asset(value) for value in requested]
        targets = [_asset(value) for value in granted_assets]
        for kind, target in targets:
            if kind == "host":
                if not any(base_kind == "host" and base == target for base_kind, base in bases):
                    return False
            elif not any(
                base_kind == "network" and target.version == base.version
                and target.subnet_of(base)
                for base_kind, base in bases
            ):
                return False
        return True
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def approved_request_is_compatible(request, *, client_id: str,
                                   grant_assets: tuple[str, ...],
                                   grant_max_risk: object,
                                   grant_created_at: str) -> bool:
    """Require exact persisted client/operator provenance and prior approval.

    request is a row containing the assessment request and joined live user
    identities. This is an eligibility check, NOT client consent.
    """
    try:
        if (
            request is None
            or request["client_id"] != client_id
            or request["status"] != "approved"
            or request["requested_mode"] != "authorized_assessment"
            or request["requester_role"] not in ("client_admin", "client_member")
            or request["requester_client"] != client_id
            or request["reviewer_role"] != "operator"
            or request["reviewer_client"] is not None
            or request["requested_by"] == request["decided_by"]
        ):
            return False
        # Enum/int confusion is denied; callers must pass the numeric enum value.
        if type(grant_max_risk) is not int:
            return False
        requested_risk = request["requested_risk"]
        if type(requested_risk) is not int or not (1 <= grant_max_risk <= requested_risk <= 4):
            return False
        created = datetime.fromisoformat(request["created_at"])
        decided = datetime.fromisoformat(request["decided_at"])
        grant_time = datetime.fromisoformat(grant_created_at)
        if any(instant.tzinfo is None or instant.utcoffset() is None
               for instant in (created, decided, grant_time)):
            return False
        if not (created <= decided <= grant_time):
            return False
        return assets_within_approved_request(request["requested_assets_json"], grant_assets)
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError):
        return False
