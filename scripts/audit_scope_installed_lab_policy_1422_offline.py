"""Offline exact-source ScopePolicy admission audit for issue #1422.

Diagnostic only. Never grants scope, permits, dispatch, merge or release.
Uses fixed fictional address literals, no DNS or network activity.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

# Audit the source from THIS checkout, not a similarly named installed package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


# Explicit membership reference. Do not use ipaddress.is_private/is_global
# because their special-purpose semantics vary by Python release.
LAB = (
    ("127.0.0.1", "127.0.0.1", ScopeReason.LOOPBACK),
    ("127.255.255.254", "127.255.255.254", ScopeReason.LOOPBACK),
    ("[::1]", "::1", ScopeReason.LOOPBACK),
    ("10.0.0.1", "10.0.0.1", ScopeReason.PRIVATE_LAB),
    ("10.255.255.254", "10.255.255.254", ScopeReason.PRIVATE_LAB),
    ("172.16.0.1", "172.16.0.1", ScopeReason.PRIVATE_LAB),
    ("172.31.255.254", "172.31.255.254", ScopeReason.PRIVATE_LAB),
    ("192.168.0.1", "192.168.0.1", ScopeReason.PRIVATE_LAB),
    ("192.168.255.254", "192.168.255.254", ScopeReason.PRIVATE_LAB),
    ("[fc00::1]", "fc00::1", ScopeReason.PRIVATE_LAB),
    ("[fdff:ffff::1]", "fdff:ffff::1", ScopeReason.PRIVATE_LAB),
)
NOT_LAB = (
    "0.0.0.0", "255.255.255.255",
    "192.0.2.1", "198.51.100.1", "203.0.113.1",
    "198.18.0.1", "198.19.255.254",
    "169.254.1.1", "100.64.0.1", "224.0.0.1",
    "240.0.0.1", "192.0.0.1", "8.8.8.8",
    "[::]", "[ff02::1]", "[fe80::1]", "[2001:db8::1]",
    "[::ffff:192.0.2.1]", "[::192.0.2.1]", "[2001:4860::8888]",
)
TOTAL_CHECKS = (len(LAB) + len(NOT_LAB)) * 2
_DENIAL = {
    "authorization_verified": False,
    "permit_issued": False,
    "execution_enabled": False,
    "merge_approved": False,
    "release_approved": False,
}


def _receipt(status: str) -> dict[str, object]:
    """Only fixed, privacy-minimal metadata; never echo address or exception."""
    return {
        "status": status,
        "checked_count": TOTAL_CHECKS if status == "REVIEW_ONLY" else 0,
        "total_count": TOTAL_CHECKS,
        **_DENIAL,
    }


def _canonical(decision: object) -> bool:
    return (
        type(decision) is ScopeDecision
        and type(decision.allowed) is bool
        and type(decision.reason) is ScopeReason
        and (decision.normalized_host is None
             or type(decision.normalized_host) is str)
    )


def audit_installed_scope(policy_factory=ScopePolicy) -> dict[str, object]:
    """Inspect real policy from this checkout; any failed gate holds atomically.

    The injectable factory is for unit tests ONLY, not a CLI parameter.
    """
    try:
        enabled = policy_factory(allow_private_lab=True)
        disabled = policy_factory(allow_private_lab=False)
        for literal, normalized, expected_reason in LAB:
            admitted = enabled.decide(Target(literal))
            locked = disabled.decide(Target(literal))
            if not (_canonical(admitted) and _canonical(locked)):
                return _receipt("HOLD")
            if not (
                admitted.allowed is True
                and admitted.reason is expected_reason
                and admitted.normalized_host == normalized
                and locked.normalized_host == normalized
            ):
                return _receipt("HOLD")
            if expected_reason is ScopeReason.LOOPBACK:
                if not (locked.allowed is True and locked.reason is ScopeReason.LOOPBACK):
                    return _receipt("HOLD")
            elif locked.allowed is not False:
                return _receipt("HOLD")

        for literal in NOT_LAB:
            admitted = enabled.decide(Target(literal))
            locked = disabled.decide(Target(literal))
            if not (_canonical(admitted) and _canonical(locked)):
                return _receipt("HOLD")
            if (
                admitted.allowed is not False
                or admitted.reason in (ScopeReason.LOOPBACK, ScopeReason.PRIVATE_LAB)
                or locked.allowed is not False
            ):
                return _receipt("HOLD")
    except Exception:
        return _receipt("HOLD")
    return _receipt("REVIEW_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    receipt = audit_installed_scope() if type(args) is list and not args else _receipt("HOLD")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    # A green diagnostic is NOT consent, so the process must never exit zero.
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
