"""Offline, non-authorizing tenant lab network collision review.

All inputs are self-declared inventory *text*. Never use this helper as a
target allowlist, ownership proof, consent check, grant, permit or scan gate.
No DNS, sockets, disk persistence, service import or target interaction.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys

MAX_BYTES = 32_768
MAX_RECORDS = 64
_ALLOWED_IPV4 = tuple(ipaddress.ip_network(s) for s in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
_ALLOWED_IPV6 = ipaddress.ip_network("fd00::/8")
_ID = re.compile(r"[A-Z][A-Z0-9_-]{0,23}\Z", re.ASCII)
_FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
          "merge_approved", "release_approved")


def _result(status: str, reason: str) -> dict[str, object]:
    # No tenant, address, asset, scope or alleged approval ever gets echoed.
    return {"schema_version": 1, "status": status, "reason": reason,
            **{flag: False for flag in _FLAGS}}


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(_: str) -> None:
    raise ValueError("nonfinite JSON constant")


def parse_json(raw: object) -> object:
    """One bounded ASCII JSON document; no duplicate keys or nonfinite values."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_BYTES:
        raise ValueError("invalid JSON byte size or type")
    try:
        # ASCII is intentional; literal Unicode escapes are rejected later
        # unless every decoded value satisfies its strict ASCII shape.
        return json.loads(raw.decode("ascii"), object_pairs_hook=_strict_pairs,
                          parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError, TypeError) as exc:
        raise ValueError("invalid JSON") from exc


def _network(value: object) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if type(value) is not str or not (1 <= len(value) <= 64):
        raise ValueError("invalid network literal")
    if not value.isascii() or value != value.strip() or "%" in value:
        raise ValueError("invalid network literal")
    if "/" not in value or "://" in value or "[" in value or "]" in value:
        raise ValueError("CIDR required")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("noncanonical CIDR") from exc
    if str(network) != value:
        raise ValueError("CIDR textual alias")
    if isinstance(network, ipaddress.IPv4Network):
        if not any(network.subnet_of(allowed) for allowed in _ALLOWED_IPV4):
            raise ValueError("outside ordinary RFC1918 lab")
    elif not network.subnet_of(_ALLOWED_IPV6):
        raise ValueError("outside assigned IPv6 ULA lab")
    return network


def _exact_id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def review_network_inventory(document: object) -> dict[str, object]:
    """Return HOLD for any duplicate or overlapping CIDR, including cross-tenant.

    REVIEW_ONLY means only the text is non-overlapping and narrowly shaped.
    It NEVER attests that a tenant exists or owns an address range.
    """
    if (type(document) is not dict
            or set(document) != {"schema_version", "networks"}
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1):
        return _result("HOLD", "INVALID_DOCUMENT_SHAPE")
    entries = document["networks"]
    if type(entries) is not list or not (1 <= len(entries) <= MAX_RECORDS):
        return _result("HOLD", "INVALID_RECORD_COUNT")

    parsed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    ids: set[tuple[str, str]] = set()
    for entry in entries:
        if (type(entry) is not dict
                or set(entry) != {"tenant_id", "scope_id", "cidr"}):
            return _result("HOLD", "INVALID_RECORD_SHAPE")
        tenant, scope = entry["tenant_id"], entry["scope_id"]
        if not _exact_id(tenant) or not _exact_id(scope):
            return _result("HOLD", "INVALID_IDENTITY_SHAPE")
        if (tenant, scope) in ids:
            return _result("HOLD", "DUPLICATE_SCOPE_ID")
        ids.add((tenant, scope))
        try:
            current = _network(entry["cidr"])
        except ValueError:
            return _result("HOLD", "INVALID_NETWORK")
        for prior in parsed:
            # Different IP families cannot share IP addresses.
            if prior.version == current.version and prior.overlaps(current):
                return _result("HOLD", "OVERLAPPING_NETWORKS")
        parsed.append(current)
    return _result("REVIEW_ONLY", "DISJOINT_LAB_NETWORK_SHAPES_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = _result("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        try:
            document = parse_json(sys.stdin.buffer.read(MAX_BYTES + 1))
            result = review_network_inventory(document)
        except ValueError:
            result = _result("HOLD", "INVALID_DOCUMENT_JSON")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # A shell's && must never treat a review-only outcome as authorization.
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
