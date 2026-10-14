"""Independent read-only literal lab-address shape review.

This is NOT a scope policy, grant validator, trusted lab inventory, or scan permit.
No DNS, sockets, target connections, filesystem writes, or LightUp runtime imports.
"""
from __future__ import annotations

import ipaddress
import json
import sys

_V4_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_V4_PRIVATE = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_V6_LOCAL_ASSIGNED = ipaddress.ip_network("fd00::/8")
_V6_LOOPBACK = ipaddress.ip_address("::1")
_MAX_INPUT_BYTES = 256
_MAX_LITERAL_CHARS = 128


def _receipt(status: str, reason: str, address_class: str = "none") -> dict[str, object]:
    # Never return the original input, purported owner, address, or consent reference.
    return {
        "schema_version": 1,
        "status": status,
        "reason": reason,
        "address_class": address_class,
        "authorization_verified": False,
        "permit_issued": False,
        "execution_enabled": False,
        "merge_approved": False,
        "release_approved": False,
    }


def review_literal(value: object) -> dict[str, object]:
    """Screen exact ASCII IP literals; REVIEW_ONLY never establishes asset ownership.

    Deliberately excludes all URL, hostname, CIDR, IPv6 zone-id, and port syntaxes.
    Accepting a *shape* is not a statement that the address belongs to a lab.
    """
    if type(value) is not str:
        return _receipt("HOLD", "INVALID_LITERAL")
    if not value or len(value) > _MAX_LITERAL_CHARS or not value.isascii():
        return _receipt("HOLD", "INVALID_LITERAL")
    if value != value.strip() or "%" in value or "/" in value:
        return _receipt("HOLD", "INVALID_LITERAL")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return _receipt("HOLD", "INVALID_LITERAL")

    if isinstance(address, ipaddress.IPv4Address):
        if address in _V4_LOOPBACK:
            return _receipt("REVIEW_ONLY", "LAB_LITERAL_SHAPE_ONLY", "loopback")
        if any(address in network for network in _V4_PRIVATE):
            return _receipt("REVIEW_ONLY", "LAB_LITERAL_SHAPE_ONLY", "rfc1918")
    elif isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return _receipt("HOLD", "OUTSIDE_LAB_LITERAL_CLASSES")
        if address == _V6_LOOPBACK:
            return _receipt("REVIEW_ONLY", "LAB_LITERAL_SHAPE_ONLY", "loopback")
        if address in _V6_LOCAL_ASSIGNED:
            return _receipt("REVIEW_ONLY", "LAB_LITERAL_SHAPE_ONLY", "ula")

    return _receipt("HOLD", "OUTSIDE_LAB_LITERAL_CLASSES")


def _from_stdin() -> dict[str, object]:
    # One bounded input; never echo it, even when JSON serialization fails.
    raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    if len(raw) > _MAX_INPUT_BYTES:
        return _receipt("HOLD", "INPUT_TOO_LARGE")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError:
        return _receipt("HOLD", "INVALID_LITERAL")
    return review_literal(value)


def main() -> int:
    receipt = (
        _from_stdin()
        if len(sys.argv) == 1
        else _receipt("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    # HOLD is a nonzero shell condition, but REVIEW_ONLY still never authorizes.
    return 0 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
