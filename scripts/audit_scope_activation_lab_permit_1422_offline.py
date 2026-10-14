"""Offline non-authorizing audit of the real LAB_ONLY permit boundary.

Issue #1422. No targets are contacted; all values are synthetic IP literals.
This MUST NOT be used as a scan, permission, grant, merge or release gate.
"""
from __future__ import annotations

import builtins
from datetime import datetime, timezone
import json
import os
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import MappingProxyType
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

_DENIED = MappingProxyType({
    "authorization_verified": False,
    "permit_issued": False,
    "execution_enabled": False,
    "scan_allowed": False,
    "merge_approved": False,
    "release_approved": False,
})


def _unexpected_io(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError("scope activation audit attempted prohibited Python I/O")


def audit() -> dict[str, object]:
    """Inspect production-shaped in-memory decisions, never authorize anything.

    A diagnostic invocation of ActivationGate.issue may return an *in-memory*
    ExecutionPermit for test inputs. Its ID is mocked to a constant and never
    exposed; it is not saved or passed to an executor or external adapter.
    """
    violations = 0
    checked = 0
    synthetic_mints = 0
    invalid_mint_requests = 0

    def _synthetic_mint(_length: int = 24) -> str:
        nonlocal synthetic_mints, invalid_mint_requests
        synthetic_mints += 1
        # Source currently calls token_urlsafe(24). A zero-length,
        # type-confused or downgraded entropy request cannot pass merely
        # because this test deliberately returns a fixed fake token.
        if type(_length) is not int or _length != 24:
            invalid_mint_requests += 1
        return SYNTHETIC_PERMIT_ID

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
        # Defense-in-depth for this synthetic Python process (NOT an OS sandbox).
        # All first-party modules are imported before the temporary I/O guards.
        with (
            patch("lightup.activation.token_urlsafe", side_effect=_synthetic_mint),
            patch.object(socket, "socket", side_effect=_unexpected_io),
            patch.object(socket, "getaddrinfo", side_effect=_unexpected_io),
            patch.object(socket, "gethostbyname", side_effect=_unexpected_io),
            patch.object(builtins, "open", side_effect=_unexpected_io),
            patch.object(Path, "open", side_effect=_unexpected_io),
            patch.object(os, "open", side_effect=_unexpected_io),
            patch.object(os, "write", side_effect=_unexpected_io),
            patch.object(os, "system", side_effect=_unexpected_io),
            patch.object(sqlite3, "connect", side_effect=_unexpected_io),
            patch.object(subprocess, "Popen", side_effect=_unexpected_io),
        ):
            for literal in SAFE_LAB + NOT_LAB:
                checked += 1
                expected_lab = literal in SAFE_LAB
                before_mints = synthetic_mints
                before_invalid_requests = invalid_mint_requests
                rejected = False
                bad_permit = False
                try:
                    issued_not_before = datetime.now(timezone.utc)
                    permit = gate.issue(Target(literal), CAPABILITY)
                    issued_not_after = datetime.now(timezone.utc)
                except PermissionError:
                    rejected = True
                else:
                    bad_permit = (
                        type(permit) is not ExecutionPermit
                        or permit.mode is not ActivationMode.LAB_ONLY
                        or type(permit.permit_id) is not str
                        or permit.permit_id != SYNTHETIC_PERMIT_ID
                        or type(permit.capability_id) is not str
                        or permit.capability_id != CAPABILITY
                        or type(permit.target) is not str
                        or permit.target != (literal[1:-1] if literal.startswith("[") else literal)
                        or type(permit.activation_reference) is not str
                        or permit.activation_reference != "LAB"
                        or type(permit.issued_at) is not datetime
                        or permit.issued_at.tzinfo is None
                        or permit.issued_at.utcoffset() is None
                        or not (issued_not_before <= permit.issued_at <= issued_not_after)
                    )
                # A denial is not clean if a synthetic token was minted
                # before PermissionError, and a lab permit must have exactly
                # one mint. Count each observation at most once.
                expected_mints = 1 if expected_lab and not rejected else 0
                if (
                    rejected == expected_lab
                    or bad_permit
                    or synthetic_mints - before_mints != expected_mints
                    or invalid_mint_requests != before_invalid_requests
                ):
                    violations += 1

                # Public/special IPs stay denied if private-lab shortcut off.
                # True loopback legitimately remains LOOPBACK under this switch.
                if not literal.startswith(("127.", "[::1]")):
                    checked += 1
                    before_mints = synthetic_mints
                    before_invalid_requests = invalid_mint_requests
                    denied = False
                    try:
                        locked_gate.issue(Target(literal), CAPABILITY)
                    except PermissionError:
                        denied = True
                    if (
                        not denied
                        or synthetic_mints != before_mints
                        or invalid_mint_requests != before_invalid_requests
                    ):
                        violations += 1

                # PLAN_ONLY must never mint a token for any sample.
                checked += 1
                before_mints = synthetic_mints
                before_invalid_requests = invalid_mint_requests
                denied = False
                try:
                    plan_gate.issue(Target(literal), CAPABILITY)
                except PermissionError:
                    denied = True
                if (
                    not denied
                    or synthetic_mints != before_mints
                    or invalid_mint_requests != before_invalid_requests
                ):
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
