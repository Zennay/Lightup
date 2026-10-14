"""Issue #1422: bounded offline IPv4/IPv6 auto-lab admission sweep (review only).

An intentionally uninstalled diagnostic for the checked-out ScopePolicy.
It never contacts, resolves, scans, or authorizes any address.
"""
from __future__ import annotations

import json
from pathlib import Path
from ipaddress import IPv6Address
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason

TOTAL_DECISIONS = 15360

def _samples():
    # Two bounded samples in every /8, and full second-octet sweeps
    # around RFC1918's 172.16/12 and 192.168/16 membership boundaries.
    for first in range(256):
        yield f"{first}.0.0.2", first, 0
        yield f"{first}.255.255.254", first, 255
    for second in range(256):
        yield f"172.{second}.0.1", 172, second
        yield f"192.{second}.0.1", 192, second
    # Deep bounded third-octet slices in special-purpose (not lab) and
    # legitimate private-use first-octet ranges. A single bad address
    # near the end must invalidate the *whole* advisory report.
    for first in (100, 169, 172, 192, 198):
        for second in range(256):
            for third in (1, 64, 128, 254):
                yield f"{first}.{second}.{third}.1", first, second


def _expected(first: int, second: int, lab_enabled: bool):
    if first == 127:
        return True, ScopeReason.LOOPBACK
    private = (
        first == 10
        or (first == 172 and 16 <= second <= 31)
        or (first == 192 and second == 168)
    )
    if lab_enabled and private:
        return True, ScopeReason.PRIVATE_LAB
    return False, ScopeReason.OUT_OF_SCOPE


def _samples_ipv6():
    # All 256 IPv6 first-byte classes, plus all 256 second-byte boundaries
    # inside each of fc00::/8 and fd00::/8 (combined RFC4193 fc00::/7).
    for first in range(256):
        addr = IPv6Address((first << 120) | 1)
        yield f"[{addr.compressed}]", addr.compressed, first
    for first in (0xFC, 0xFD):
        for second in range(256):
            addr = IPv6Address((first << 120) | (second << 112) | 2)
            yield f"[{addr.compressed}]", addr.compressed, first

    # IPv4 hidden inside an IPv6 authority is never implicitly trusted
    # by its RFC1918/loopback inner bytes: mapped, 6to4 and NAT64 are
    # separate network/translation contexts requiring explicit review.
    for ipv4_first in range(256):
        ipv4_literal = f"{ipv4_first}.0.0.1"
        for encoded in (
            f"::ffff:{ipv4_literal}",
            f"2002:{ipv4_first:02x}00:1::1",
            f"64:ff9b::{ipv4_literal}",
        ):
            addr = IPv6Address(encoded)
            yield f"[{addr.compressed}]", addr.compressed, int(addr) >> 120


def _expected_ipv6(normalized: str, first: int, lab_enabled: bool):
    if normalized == "::1":
        return True, ScopeReason.LOOPBACK
    if lab_enabled and first in (0xFC, 0xFD):
        return True, ScopeReason.PRIVATE_LAB
    return False, ScopeReason.OUT_OF_SCOPE


def _receipt(status: str, count: int, diagnostic_code: str):
    # Only fixed public constants, never target, owner, hostname or exception.
    return {
        "status": status,
        "diagnostic_code": diagnostic_code,
        "checked_count": count,
        "total_count": TOTAL_DECISIONS,
        "authorization_verified": False,
        "permit_issued": False,
        "execution_enabled": False,
        "merge_approved": False,
        "release_approved": False,
    }


def _decision_mismatch(actual, normalized, expected_allowed, expected_reason):
    """Return a bounded public category, never a rejected target or secret."""
    if (
        type(actual) is not ScopeDecision
        or type(actual.allowed) is not bool
        or type(actual.reason) is not ScopeReason
        or type(actual.normalized_host) is not str
    ):
        return "RESULT_TYPE_MISMATCH"
    if actual.normalized_host != normalized:
        return "HOST_IDENTITY_MISMATCH"
    if actual.allowed is not expected_allowed or actual.reason is not expected_reason:
        return "SCOPE_CLASSIFICATION_MISMATCH"
    return None


def review_ipv4_octet_sweep(policy_factory=ScopePolicy):
    """Never return an authorizing receipt, even if all checks pass.

    REVIEW_ONLY means that the fixed source-behavior matrix matched, NOT
    that a real lab or customer has approved even one target.
    """
    try:
        checked = 0
        for lab_enabled in (True, False):
            policy = policy_factory(
                allow_private_lab=lab_enabled,
                explicit_hosts=frozenset(),
                explicit_networks=(),
                require_authorization_for_public=True,
            )
            for literal, first, second in _samples():
                actual = policy.decide(Target(literal))
                expected_allowed, expected_reason = _expected(
                    first, second, lab_enabled
                )
                mismatch = _decision_mismatch(
                    actual, literal, expected_allowed, expected_reason
                )
                if mismatch is not None:
                    return _receipt("HOLD", 0, mismatch)
                checked += 1
            for literal, normalized, first in _samples_ipv6():
                actual = policy.decide(Target(literal))
                expected_allowed, expected_reason = _expected_ipv6(
                    normalized, first, lab_enabled
                )
                mismatch = _decision_mismatch(
                    actual, normalized, expected_allowed, expected_reason
                )
                if mismatch is not None:
                    return _receipt("HOLD", 0, mismatch)
                checked += 1
        if checked != TOTAL_DECISIONS:
            return _receipt("HOLD", 0, "SAMPLE_COUNT_MISMATCH")
    except Exception:
        return _receipt("HOLD", 0, "EVALUATION_EXCEPTION")
    return _receipt("REVIEW_ONLY", checked, "MATCHED_NON_AUTHORIZING")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    # Exact, zero-argument interface. Never read stdin or echo raw input.
    receipt = (
        review_ipv4_octet_sweep()
        if type(argv) is list and len(argv) == 0
        else _receipt("HOLD", 0, "ARGUMENT_REJECTED")
    )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    # REVIEW_ONLY also exits nonzero: it is NOT consent or release.
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
