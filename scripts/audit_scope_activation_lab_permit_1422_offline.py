"""Offline non-authorizing audit of the real LAB_ONLY permit boundary.

Issue #1422. No targets are contacted; all values are synthetic IP literals.
This MUST NOT be used as a scan, permission, grant, merge or release gate.
"""
from __future__ import annotations

import json
import socket
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy, ExecutionPermit
from lightup.models import Target
from lightup.scope import ScopePolicy

# Unroutable synthetic inputs only. These are classification fixtures, not targets.
SAFE_LAB = (
    "127.0.0.1", "[::1]", "10.1.2.3", "172.16.0.1",
    "192.168.1.1", "[fd00::1]",
)
NOT_LAB = (
    "192.0.2.1", "198.51.100.1", "203.0.113.1",
    "198.18.0.1", "0.0.0.0", "255.255.255.255",
    "[2001:db8::1]", "169.254.1.1",
    "[::ffff:192.0.2.1]", "[fe80::1]",
)
CAPABILITY = "synthetic_reference_only"
SYNTHETIC_PERMIT_ID = "NO_REAL_PERMIT"

_DENIED = {
    "authorization_verified": False,
    "permit_issued": False,
    "execution_enabled": False,
    "scan_allowed": False,
    "merge_approved": False,
    "release_approved": False,
}


def _unexpected_io(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError("scope activation audit attempted network I/O")


def audit() -> dict[str, object]:
    """Inspect production-shaped in-memory decisions, never authorize anything.

    A diagnostic invocation of ActivationGate.issue may return an *in-memory*
    ExecutionPermit for test inputs. Its ID is mocked to a constant and never
    exposed; it is not saved or passed to an executor or external adapter.
    """
    violations = 0
    checked = 0
    try:
        gate = ActivationGate(
            ScopePolicy(allow_private_lab=True),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )
        locked_gate = ActivationGate(
            ScopePolicy(allow_private_lab=False),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )
        plan_gate = ActivationGate(
            ScopePolicy(allow_private_lab=True),
            ActivationPolicy(mode=ActivationMode.PLAN_ONLY),
        )
        # Block accidental resolver/connection use as an extra synthetic guard.
        with (
            patch("lightup.activation.token_urlsafe", return_value=SYNTHETIC_PERMIT_ID),
            patch.object(socket, "socket", side_effect=_unexpected_io),
            patch.object(socket, "getaddrinfo", side_effect=_unexpected_io),
            patch.object(socket, "gethostbyname", side_effect=_unexpected_io),
        ):
            for literal in SAFE_LAB + NOT_LAB:
                checked += 1
                expected_lab = literal in SAFE_LAB
                try:
                    permit = gate.issue(Target(literal), CAPABILITY)
                except PermissionError:
                    # A reserved, benchmark, documentation or link-local
                    # address MUST be denied; permitted lab samples should pass.
                    if expected_lab:
                        violations += 1
                else:
                    if (
                        not expected_lab
                        or type(permit) is not ExecutionPermit
                        or permit.mode is not ActivationMode.LAB_ONLY
                        or permit.permit_id != SYNTHETIC_PERMIT_ID
                        or permit.capability_id != CAPABILITY
                    ):
                        violations += 1

                # Public/special IPs stay denied if private-lab shortcut off.
                # True loopback legitimately remains LOOPBACK under this switch.
                if not literal.startswith(("127.", "[::1]")):
                    checked += 1
                    try:
                        locked_gate.issue(Target(literal), CAPABILITY)
                    except PermissionError:
                        pass
                    else:
                        violations += 1

                # PLAN_ONLY must never mint a token for any sample.
                checked += 1
                try:
                    plan_gate.issue(Target(literal), CAPABILITY)
                except PermissionError:
                    pass
                else:
                    violations += 1
    except Exception:
        # Corrupt source, unanticipated API drift or attempted I/O is HOLD.
        return {"status": "HOLD", "checked": 0, "violations": 1, **_DENIED}
    return {
        "status": "HOLD" if violations else "REVIEW_ONLY",
        "checked": checked,
        "violations": violations,
        **_DENIED,
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    result = audit() if not args else {
        "status": "HOLD", "checked": 0, "violations": 1, **_DENIED,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    # Deliberately nonzero even when all synthetic checks match.
    return 2 if result["status"] == "HOLD" else 3


if __name__ == "__main__":
    raise SystemExit(main())
