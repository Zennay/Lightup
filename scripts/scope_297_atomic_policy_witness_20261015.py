"""Offline, non-authorizing installed-source demonstration for LightUp issue #297.

All case inputs are hardcoded documentation-only examples. No user targets,
customer grants, filesystem writes, outbound sockets, or network resolution.
Every operational invocation returns exit 2 / HOLD, even when no defect is seen.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from types import MappingProxyType
import socket
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason, ScopeDecision


@dataclass(frozen=True)
class Case:
    case_id: str
    target: str
    hosts: frozenset
    networks: tuple[str, ...]
    expected_unsafe_reason: ScopeReason
    needs_synthetic_grant: bool = True
    require_authorization: bool = True


HOST = "security.example.test"
DOCUMENTATION_IP = "198.51.100.42"
DOCUMENTATION_NET = "198.51.100.0/24"
FAKE_GRANT = Authorization(
    owner="invented-test-owner",
    reference="SYNTHETIC-NOT-A-REAL-GRANT",
    valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
    valid_until=datetime(2090, 1, 1, tzinfo=timezone.utc),
)
CASES = (
    Case("network_non_cidr_to_host", HOST, frozenset({HOST}), ("not-a-cidr",), ScopeReason.EXPLICIT_HOST),
    Case("network_bad_ipv4_prefix_to_host", HOST, frozenset({HOST}), ("198.51.100.0/129",), ScopeReason.EXPLICIT_HOST),
    Case("network_mixed_to_host", HOST, frozenset({HOST}), (DOCUMENTATION_NET, "invalid-cidr"), ScopeReason.EXPLICIT_HOST),
    Case("network_bad_ipv6_prefix_to_host", HOST, frozenset({HOST}), ("2001:db8::/999",), ScopeReason.EXPLICIT_HOST),
    Case("network_bad_to_host_without_auth_flag", HOST, frozenset({HOST}), ("invalid",), ScopeReason.EXPLICIT_HOST, False, False),
    Case("network_bad_to_url_host", "https://security.example.test/example", frozenset({HOST}), ("bad-network",), ScopeReason.EXPLICIT_HOST),
    Case("host_non_string_to_network", DOCUMENTATION_IP, frozenset({42}), (DOCUMENTATION_NET,), ScopeReason.EXPLICIT_NETWORK),
    Case("host_bytes_to_network", DOCUMENTATION_IP, frozenset({b"security.example.test"}), (DOCUMENTATION_NET,), ScopeReason.EXPLICIT_NETWORK),
)

FROZEN_FALSE_PERMISSIONS = MappingProxyType({
    "can_authorize": False,
    "can_grant": False,
    "can_scan": False,
    "can_merge": False,
    "can_deploy": False,
    "can_release": False,
})


class NetworkAttemptBlocked(RuntimeError):
    """Synthetic network tripwire. No socket or DNS call can escape."""


class NetworkTripwire:
    """Count attempted networking even if a caller suppresses the exception."""

    def __init__(self):
        self.attempts = 0

    def block(self, *_args, **_kwargs):
        self.attempts += 1
        raise NetworkAttemptBlocked("network forbidden")


@contextmanager
def disconnected():
    tripwire = NetworkTripwire()
    with ExitStack() as stack:
        # Pure in-process tripwire, not a host-level network sandbox.
        # Patch the most common stdlib socket/DNS entry points rather than
        # relying on getaddrinfo() as the only resolver route.
        for api in (
            "socket",
            "socketpair",
            "create_connection",
            "create_server",
            "getaddrinfo",
            "gethostbyname",
            "gethostbyname_ex",
            "gethostbyaddr",
            "getnameinfo",
            "getfqdn",
        ):
            stack.enter_context(
                patch.object(socket, api, side_effect=tripwire.block)
            )
        yield tripwire


def evaluate() -> dict:
    """Evaluate only the eight pinned synthetic cases; NEVER return authority."""
    observations = []
    with disconnected() as tripwire:
        for case in CASES:
            attempts_before = tripwire.attempts
            try:
                # A future strict constructor may reject malformed policy
                # before decide(): that is REVIEW, not a CLI crash or a GO.
                policy = ScopePolicy(
                    allow_private_lab=False,
                    explicit_hosts=case.hosts,
                    explicit_networks=case.networks,
                    require_authorization_for_public=case.require_authorization,
                )
                decision = policy.decide(Target(
                    case.target,
                    authorization=FAKE_GRANT if case.needs_synthetic_grant else None,
                ))
                if decision.allowed:
                    classification = (
                        "UNSAFE_ALLOW"
                        if decision.reason == case.expected_unsafe_reason
                        else "OTHER_ALLOW_REVIEW"
                    )
                else:
                    classification = "DENIED_REVIEW"
            except NetworkAttemptBlocked:
                # Socket/DNS was stopped before I/O; distinct from source errors.
                classification = "NETWORK_BLOCKED_REVIEW"
            except Exception:
                # Do not expose exception strings: could contain private config.
                classification = "ERROR_REVIEW"
            # A caller may catch NetworkAttemptBlocked and return a normal
            # decision. The attempt still happened and must not disappear.
            if tripwire.attempts > attempts_before:
                classification = "NETWORK_BLOCKED_REVIEW"
            observations.append({
                "case_id": case.case_id,
                "classification": classification,
            })
    classifications = [item["classification"] for item in observations]
    return {
        "issue": 297,
        "status": "HOLD",
        "is_real_grant": False,
        "is_real_target_assessment": False,
        "permissions": dict(FROZEN_FALSE_PERMISSIONS),
        "case_count": len(CASES),
        "unsafe_allow_count": classifications.count("UNSAFE_ALLOW"),
        "other_allow_review_count": classifications.count("OTHER_ALLOW_REVIEW"),
        "denied_review_count": classifications.count("DENIED_REVIEW"),
        "error_review_count": classifications.count("ERROR_REVIEW"),
        "network_blocked_review_count": classifications.count("NETWORK_BLOCKED_REVIEW"),
        "observations": observations,
    }


def render_dutch(receipt: dict) -> str:
    by_id = {
        item["case_id"]: item["classification"] for item in receipt["observations"]
    }
    network_to_host = sum(
        status == "UNSAFE_ALLOW"
        for case_id, status in by_id.items()
        if case_id.startswith("network_")
    )
    host_to_network = sum(
        status == "UNSAFE_ALLOW"
        for case_id, status in by_id.items()
        if case_id.startswith("host_")
    )
    lines = [
        "LightUp #297 — offline autorisatieproef met fictieve gegevens",
        "UITKOMST: HOLD — geen toestemming, scan, grant of vrijgave",
        f"Gecontroleerde paden: {receipt['case_count']}",
        f"Onveilige toestemmingen gezien: {receipt['unsafe_allow_count']}",
        f"Fout netwerkbeleid omzeild via hostnaam: {network_to_host}",
        f"Fout hostbeleid omzeild via IP-netwerk: {host_to_network}",
        f"Andere toestemmingen voor review: {receipt['other_allow_review_count']}",
        f"Weigeringen voor review: {receipt['denied_review_count']}",
        f"Fouten voor review: {receipt['error_review_count']}",
        f"Gestopte netwerkpogingen voor review: {receipt['network_blocked_review_count']}",
        "Details (alleen fictieve casuscodes):",
    ]
    for item in receipt["observations"]:
        lines.append(f"  {item['case_id']}: {item['classification']}")
    lines.append(
        "Herstelroute: valideer al het host- en netwerkbeleid samen, vóór publieke toegang."
    )
    lines.append(
        "Let op: alleen originele geïnstalleerde broncode + CI + eigenaar mogen vrijgave onderbouwen."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Synthetic current-source scope diagnostics; never authorization."
    )
    parser.add_argument("--json", action="store_true", help="Machine-readable HOLD receipt")
    args = parser.parse_args(argv)
    receipt = evaluate()
    if args.json:
        print(json.dumps(receipt, sort_keys=True, ensure_ascii=True))
    else:
        print(render_dutch(receipt))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
