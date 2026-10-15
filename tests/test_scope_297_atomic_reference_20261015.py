"""#297 isolated in-memory reference acceptance; NOT an installed scope fix.

Only fictional, hardcoded in-process objects are touched. The real owner of
ScopePolicy must implement and independently review any actual source change.
"""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_network
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))

from lightup.models import Authorization, Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason
import scope_297_atomic_policy_witness_20261015 as report
import test_scope_297_current_main_atomic_public_config_20261015 as source_tests

ORIGINAL_DECIDE = ScopePolicy.decide
REFERENCE_DENIAL_REASON = ScopeReason.INVALID_TARGET

FAKE_VALID_GRANT = Authorization(
    owner="synthetic_reference_test_only",
    reference="NOT_REAL_CONSENT",
    valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
    valid_until=datetime(2090, 1, 1, tzinfo=timezone.utc),
)
FAKE_EXPIRED_GRANT = Authorization(
    owner="synthetic_reference_test_only",
    reference="EXPIRED_NOT_CONSENT",
    valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
    valid_until=datetime(2021, 1, 1, tzinfo=timezone.utc),
)


def reference_atomic_decide(policy: ScopePolicy, target: Target) -> ScopeDecision:
    """Test-only security invariant, not a public validator or production patch.

    The preview declines every decision if *any* explicit public-scope host
    or network entry is ill-typed or malformed, before even checking host
    versus IP branches. For fully shaped policies, delegate unchanged to
    the real installed ScopePolicy.decide.
    """
    try:
        if type(policy.explicit_hosts) is not frozenset:
            return ScopeDecision(False, None, REFERENCE_DENIAL_REASON)
        if type(policy.explicit_networks) is not tuple:
            return ScopeDecision(False, None, REFERENCE_DENIAL_REASON)
        if any(type(host) is not str for host in policy.explicit_hosts):
            return ScopeDecision(False, None, REFERENCE_DENIAL_REASON)
        for item in policy.explicit_networks:
            if type(item) is not str:
                return ScopeDecision(False, None, REFERENCE_DENIAL_REASON)
            ip_network(item, strict=False)
    except (TypeError, ValueError, AttributeError, OverflowError):
        return ScopeDecision(False, None, REFERENCE_DENIAL_REASON)
    return ORIGINAL_DECIDE(policy, target)


class AtomicPolicyReferenceAcceptance(unittest.TestCase):
    """The reference test never creates a usable permit or source-level fix."""

    def setUp(self):
        self.dns = patch.object(
            socket, "getaddrinfo", side_effect=AssertionError("NO_DNS")
        )
        self.network = patch.object(
            socket, "socket", side_effect=AssertionError("NO_NETWORK")
        )
        self.dns.start()
        self.network.start()
        self.addCleanup(self.network.stop)
        self.addCleanup(self.dns.stop)

    def test_all_ten_installed_source_red_contracts_pass_under_reference_guard(self):
        original_reds = [
            name for name in dir(source_tests.AtomicPublicConfigurationSourceContract)
            if name.startswith("test_red_")
        ]
        self.assertEqual(len(original_reds), 10)
        with patch.object(ScopePolicy, "decide", reference_atomic_decide):
            for name in original_reds:
                with self.subTest(original_red_name=name):
                    real_case = source_tests.AtomicPublicConfigurationSourceContract(name)
                    real_case.setUp()
                    try:
                        # Direct call bypasses expectedFailure runner handling:
                        # a missing denial raises AssertionError here.
                        getattr(real_case, name)()
                    finally:
                        real_case.doCleanups()

    def test_all_eight_cli_cases_become_denials_but_never_release(self):
        with patch.object(ScopePolicy, "decide", reference_atomic_decide):
            receipt = report.evaluate()
            self.assertEqual(receipt["case_count"], 8)
            self.assertEqual(receipt["denied_review_count"], 8)
            self.assertEqual(receipt["unsafe_allow_count"], 0)
            self.assertEqual(receipt["error_review_count"], 0)
            self.assertEqual(receipt["status"], "HOLD")
            self.assertEqual(receipt["permissions"], report.FROZEN_FALSE_PERMISSIONS)
            self.assertFalse(any(receipt["permissions"].values()))

    def test_reference_refuses_bad_network_even_for_explicit_host(self):
        cases = ("not-a-cidr", "198.51.100.0/33", "2001:db8::/129")
        with patch.object(ScopePolicy, "decide", reference_atomic_decide):
            for cidr in cases:
                with self.subTest(bad_cidr=cidr):
                    policy = ScopePolicy(
                        allow_private_lab=False,
                        explicit_hosts=frozenset({"security.example.test"}),
                        explicit_networks=(cidr,),
                    )
                    d = policy.decide(Target("security.example.test", FAKE_VALID_GRANT))
                    self.assertFalse(d.allowed)

    def test_reference_refuses_bad_host_even_for_explicit_network(self):
        for host in (23, b"invalid.example.test", None, ("tuple",)):
            with self.subTest(bad_host_type=type(host).__name__):
                policy = ScopePolicy(
                    allow_private_lab=False,
                    explicit_hosts=frozenset({host}),
                    explicit_networks=("198.51.100.0/24",),
                )
                with patch.object(ScopePolicy, "decide", reference_atomic_decide):
                    d = policy.decide(Target("198.51.100.42", FAKE_VALID_GRANT))
                self.assertFalse(d.allowed)

    def test_reference_keeps_valid_ipv4_ipv6_and_hostname_permits(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("198.51.100.0/24", "2001:db8::/32"),
        )
        targets = (
            ("security.example.test", ScopeReason.EXPLICIT_HOST),
            ("198.51.100.42", ScopeReason.EXPLICIT_NETWORK),
            ("https://[2001:db8::42]/", ScopeReason.EXPLICIT_NETWORK),
        )
        with patch.object(ScopePolicy, "decide", reference_atomic_decide):
            for value, reason in targets:
                with self.subTest(target=value):
                    decision = policy.decide(Target(value, FAKE_VALID_GRANT))
                    self.assertEqual((decision.allowed, decision.reason), (True, reason))

    def test_reference_keeps_expired_and_missing_grants_denied(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("198.51.100.0/24", "2001:db8::/32"),
        )
        with patch.object(ScopePolicy, "decide", reference_atomic_decide):
            for value in ("security.example.test", "198.51.100.42", "https://[2001:db8::42]/"):
                with self.subTest(value=value):
                    expired = policy.decide(Target(value, FAKE_EXPIRED_GRANT))
                    missing = policy.decide(Target(value))
                    self.assertEqual(
                        (expired.allowed, expired.reason),
                        (False, ScopeReason.AUTHORIZATION_EXPIRED),
                    )
                    self.assertEqual(
                        (missing.allowed, missing.reason),
                        (False, ScopeReason.AUTHORIZATION_MISSING),
                    )

    def test_malformed_container_shapes_fail_closed_without_exception(self):
        invalid_pairs = (
            (["security.example.test"], ("198.51.100.0/24",)),
            (frozenset({"security.example.test"}), ["198.51.100.0/24"]),
            (frozenset({"security.example.test"}), (None,)),
            (frozenset({"security.example.test"}), (b"network",)),
        )
        for hosts, networks in invalid_pairs:
            with self.subTest(host_type=type(hosts).__name__, net_type=type(networks).__name__):
                policy = ScopePolicy(
                    allow_private_lab=False, explicit_hosts=hosts,
                    explicit_networks=networks,
                )
                with patch.object(ScopePolicy, "decide", reference_atomic_decide):
                    d = policy.decide(Target("security.example.test", FAKE_VALID_GRANT))
                self.assertFalse(d.allowed)

    def test_real_installed_decide_remains_untouched_after_reference_patch(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("bad-network",),
        )
        with patch.object(ScopePolicy, "decide", reference_atomic_decide):
            self.assertFalse(
                policy.decide(Target("security.example.test", FAKE_VALID_GRANT)).allowed
            )
        self.assertIs(ScopePolicy.decide, ORIGINAL_DECIDE)
        # Current installed source remains unsafe. A test-only preview isn't a fix.
        observed = policy.decide(Target("security.example.test", FAKE_VALID_GRANT))
        self.assertEqual(
            (observed.allowed, observed.reason),
            (True, ScopeReason.EXPLICIT_HOST),
        )


if __name__ == "__main__":
    unittest.main()
