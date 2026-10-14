"""Issue #1422: bounded offline IPv4 auto-lab admission sweep (review only).

An intentionally uninstalled diagnostic for the checked-out ScopePolicy.
It never contacts, resolves, scans, or authorizes any address.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason

TOTAL_DECISIONS = 2048
_DENY_FLAGS = {
    "authorization_verified": False,
    "permit_issued": False,
    "execution_enabled": False,
    "merge_approved": False,
    "release_approved": False,
}


def _samples():
    # Two bounded samples in every /8, and full second-octet sweeps
    # around RFC1918's 172.16/12 and 192.168/16 membership boundaries.
    for first in range(256):
        yield f"{first}.0.0.1", first, 0
        yield f"{first}.255.255.254", first, 255
    for second in range(256):
        yield f"172.{second}.0.1", 172, second
        yield f"192.{second}.0.1", 192, second


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


def _receipt(status: str, count: int):
    return {
        "status": status,
        "checked_count": count,
        "total_count": TOTAL_DECISIONS,
        **_DENY_FLAGS,
    }


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
                if (
                    type(actual) is not ScopeDecision
                    or type(actual.allowed) is not bool
                    or type(actual.reason) is not ScopeReason
                    or type(actual.normalized_host) is not str
                    or actual.normalized_host != literal
                    or actual.allowed is not expected_allowed
                    or actual.reason is not expected_reason
                ):
                    return _receipt("HOLD", 0)
                checked += 1
        if checked != TOTAL_DECISIONS:
            return _receipt("HOLD", 0)
    except Exception:
        return _receipt("HOLD", 0)
    return _receipt("REVIEW_ONLY", checked)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    # Exact, zero-argument interface. Never read stdin or echo raw input.
    receipt = (
        review_ipv4_octet_sweep()
        if type(argv) is list and len(argv) == 0
        else _receipt("HOLD", 0)
    )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    # REVIEW_ONLY also exits nonzero: it is NOT consent or release.
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
