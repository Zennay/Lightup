"""Offline, non-authorizing installed-source demonstration for LightUp issue #297.

All case inputs are hardcoded documentation-only examples. No user targets,
customer grants, filesystem writes, outbound sockets, or network resolution.
Every operational invocation returns exit 2 / HOLD, even when no defect is seen.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


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

FROZEN_FALSE_PERMISSIONS = {
    "can_authorize": False,
    "can_grant": False,
    "can_scan": False,
    "can_merge": False,
    "can_deploy": False,
    "can_release": False,
}


@contextmanager
def disconnected():
    with (
        patch.object(socket, "getaddrinfo", side_effect=AssertionError("network forbidden")),
        patch.object(socket, "socket", side_effect=AssertionError("network forbidden")),
    ):
        yield


def evaluate() -> dict:
    """Evaluate only the eight pinned synthetic cases; NEVER return authority."""
    observations = []
    with disconnected():
        for case in CASES:
            policy = ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=case.hosts,
                explicit_networks=case.networks,
                require_authorization_for_public=case.require_authorization,
            )
            try:
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
            except Exception:
                # Do not expose exception strings: could contain private config.
                classification = "ERROR_REVIEW"
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
        "observations": observations,
    }


def render_dutch(receipt: dict) -> str:
    lines = [
        "LightUp #297 — offline autorisatieproef met fictieve gegevens",
        "UITKOMST: HOLD — geen toestemming, scan, grant of vrijgave",
        f"Gecontroleerde paden: {receipt['case_count']}",
        f"Onveilige toestemmingen gezien: {receipt['unsafe_allow_count']}",
        f"Andere toestemmingen voor review: {receipt['other_allow_review_count']}",
        f"Weigeringen voor review: {receipt['denied_review_count']}",
        f"Fouten voor review: {receipt['error_review_count']}",
        "Details (alleen fictieve casuscodes):",
    ]
    for item in receipt["observations"]:
        lines.append(f"  {item['case_id']}: {item['classification']}")
    lines.append("Let op: alleen originele geïnstalleerde broncode + CI + eigenaar mogen vrijgave onderbouwen.")
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
