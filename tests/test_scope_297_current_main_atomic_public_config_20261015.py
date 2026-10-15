"""#297: installed ScopePolicy atomic public-configuration admission contract.

Independent, additive current-main acceptance. Synthetic target identifiers ONLY.
Known unsafe paths remain expected failures until the scope source owner fixes them.
"""

from __future__ import annotations

import os
import socket
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


HOST = "security.example.test"
FAKE_AUTH = Authorization(
    owner="fictional-test-owner",
    reference="SYNTHETIC-NOT-CONSENT",
    valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
    valid_until=datetime(2090, 1, 1, tzinfo=timezone.utc),
)


def policy_with_bad_networks(networks, *, require_auth=True):
    return ScopePolicy(
        allow_private_lab=False,
        explicit_hosts=frozenset({HOST}),
        explicit_networks=networks,
        require_authorization_for_public=require_auth,
    )


class AtomicPublicConfigurationSourceContract(unittest.TestCase):
    """Pure in-process source characterization, never permission to scan."""

    def setUp(self):
        # This contract must not be able to contact a real target or resolve DNS.
        self.resolver = patch.object(
            socket, "getaddrinfo", side_effect=AssertionError("NO_DNS")
        )
        self.connect = patch.object(
            socket, "socket", side_effect=AssertionError("NO_NETWORK")
        )
        self.resolver.start()
        self.connect.start()
        self.addCleanup(self.connect.stop)
        self.addCleanup(self.resolver.stop)

    def assert_no_public_authority(self, policy, target=HOST, authorization=FAKE_AUTH):
        decision = policy.decide(Target(target, authorization=authorization))
        self.assertFalse(
            decision.allowed,
            "Malformed *any* public-scope config must never authorize another path",
        )

    @unittest.expectedFailure
    def test_red_non_cidr_network_cannot_be_bypassed_by_explicit_host(self):
        self.assert_no_public_authority(policy_with_bad_networks(("not-a-cidr",)))

    @unittest.expectedFailure
    def test_red_invalid_prefix_cannot_be_bypassed_by_explicit_host(self):
        self.assert_no_public_authority(policy_with_bad_networks(("198.51.100.0/129",)))

    @unittest.expectedFailure
    def test_red_mixed_valid_and_invalid_networks_poison_public_host_decision(self):
        self.assert_no_public_authority(
            policy_with_bad_networks(("203.0.113.0/24", "invalid-cidr"))
        )

    @unittest.expectedFailure
    def test_red_ipv6_bad_prefix_poison_public_host_decision(self):
        self.assert_no_public_authority(policy_with_bad_networks(("2001:db8::/999",)))

    @unittest.expectedFailure
    def test_red_public_host_must_not_bypass_bad_network_even_if_auth_disabled(self):
        self.assert_no_public_authority(
            policy_with_bad_networks(("not-a-network",), require_auth=False),
            authorization=None,
        )

    @unittest.expectedFailure
    def test_red_uri_target_must_not_bypass_bad_network(self):
        self.assert_no_public_authority(
            policy_with_bad_networks(("broken-network",)),
            target="https://security.example.test/path",
        )

    @unittest.expectedFailure
    def test_red_nonstring_host_entry_cannot_be_bypassed_by_public_ip_network(self):
        # Atomic public policy validation is bidirectional: malformed hosts
        # must not be ignored just because the chosen target is an IP literal.
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({42}),
            explicit_networks=("8.8.8.0/24",),
        )
        self.assertFalse(policy.decide(Target("8.8.8.8", FAKE_AUTH)).allowed)

    @unittest.expectedFailure
    def test_red_bytes_host_entry_cannot_be_bypassed_by_public_ip_network(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({b"security.example.test"}),
            explicit_networks=("8.8.8.0/24",),
        )
        self.assertFalse(policy.decide(Target("8.8.8.8", FAKE_AUTH)).allowed)

    def test_both_host_shape_reds_are_actual_unsafe_network_allows(self):
        # Ordinary witness: a runtime exception must not pass as RED evidence.
        for invalid_host in (42, b"security.example.test"):
            with self.subTest(invalid_host_type=type(invalid_host).__name__):
                policy = ScopePolicy(
                    allow_private_lab=False,
                    explicit_hosts=frozenset({invalid_host}),
                    explicit_networks=("8.8.8.0/24",),
                )
                decision = policy.decide(Target("8.8.8.8", FAKE_AUTH))
                self.assertEqual(
                    (decision.allowed, decision.reason),
                    (True, ScopeReason.EXPLICIT_NETWORK),
                )

    def test_canonical_host_and_network_still_authorize_with_synthetic_grant(self):
        policy = policy_with_bad_networks(("203.0.113.0/24", "2001:db8::/32"))
        decision = policy.decide(Target("https://security.example.test/page", FAKE_AUTH))
        self.assertEqual((decision.allowed, decision.reason),
                         (True, ScopeReason.EXPLICIT_HOST))

    def test_valid_network_does_not_authorize_unknown_public_host(self):
        policy = policy_with_bad_networks(("203.0.113.0/24",))
        decision = policy.decide(Target("unlisted.example.test", FAKE_AUTH))
        self.assertEqual((decision.allowed, decision.reason),
                         (False, ScopeReason.OUT_OF_SCOPE))

    def test_valid_network_without_synthetic_grant_does_not_authorize_public_ip(self):
        policy = policy_with_bad_networks(("203.0.113.0/24",))
        decision = policy.decide(Target("203.0.113.45"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_valid_public_host_without_grant_is_denied(self):
        policy = policy_with_bad_networks(("203.0.113.0/24",))
        decision = policy.decide(Target(HOST))
        self.assertEqual((decision.allowed, decision.reason),
                         (False, ScopeReason.AUTHORIZATION_MISSING))

    def test_bad_network_with_unlisted_public_host_cannot_create_authority(self):
        policy = policy_with_bad_networks(("bad",))
        decision = policy.decide(Target("not-listed.example.test", FAKE_AUTH))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_original_public_network_parse_failure_is_not_a_permit(self):
        policy = policy_with_bad_networks(("invalid",), require_auth=False)
        with self.assertRaises(ValueError):
            policy.decide(Target("8.8.8.8", FAKE_AUTH))

    def test_policy_and_network_inputs_not_mutated(self):
        networks = ("203.0.113.0/24", "2001:db8::/32")
        policy = policy_with_bad_networks(networks)
        before = (policy.explicit_hosts, policy.explicit_networks)
        policy.decide(Target(HOST, FAKE_AUTH))
        self.assertEqual(before, (policy.explicit_hosts, policy.explicit_networks))
        self.assertEqual(networks, policy.explicit_networks)

    def test_all_six_source_reds_have_actual_unsafe_allow_witnesses(self):
        # expectedFailure alone would mask a TypeError, ValueError, or mock tripwire.
        # This separate ordinary control proves the installed policy REALLY
        # returns the unsafe allow decision for every expected-RED vector.
        variants = (
            ("non_cidr", ("not-a-cidr",), HOST, True, FAKE_AUTH),
            ("bad_ipv4_prefix", ("198.51.100.0/129",), HOST, True, FAKE_AUTH),
            ("mixed_valid_invalid", ("203.0.113.0/24", "invalid-cidr"), HOST, True, FAKE_AUTH),
            ("bad_ipv6_prefix", ("2001:db8::/999",), HOST, True, FAKE_AUTH),
            ("auth_disabled", ("not-a-network",), HOST, False, None),
            ("https_host", ("broken-network",), "https://security.example.test/path", True, FAKE_AUTH),
        )
        for label, networks, target, requires_auth, auth in variants:
            with self.subTest(label=label):
                decision = policy_with_bad_networks(
                    networks, require_auth=requires_auth
                ).decide(Target(target, authorization=auth))
                self.assertEqual(
                    (decision.allowed, decision.reason),
                    (True, ScopeReason.EXPLICIT_HOST),
                    "RED must be a genuine unsafe allow, not a hidden crash",
                )

    def test_golden_canonical_ipv4_ipv6_network_permits_remain_with_valid_grant(self):
        # A future whole-config fail-closed fix must not break valid explicit
        # host/network policy. All targets are fictional documentation ranges.
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({HOST}),
            explicit_networks=("198.51.100.0/24", "2001:db8::/32"),
        )
        for value in ("198.51.100.42", "https://[2001:db8::42]/test"):
            with self.subTest(target_kind="ipv6" if "[" in value else "ipv4"):
                decision = policy.decide(Target(value, FAKE_AUTH))
                self.assertEqual(
                    (decision.allowed, decision.reason),
                    (True, ScopeReason.EXPLICIT_NETWORK),
                )

    def test_golden_canonical_public_ip_outside_networks_stays_denied(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({HOST}),
            explicit_networks=("198.51.100.0/24", "2001:db8::/32"),
        )
        for value in ("198.51.101.42", "https://[2001:db9::42]/outside"):
            with self.subTest(target_kind="ipv6" if "[" in value else "ipv4"):
                decision = policy.decide(Target(value, FAKE_AUTH))
                self.assertEqual(
                    (decision.allowed, decision.reason),
                    (False, ScopeReason.OUT_OF_SCOPE),
                )

    def test_golden_canonical_expired_grant_denies_host_and_ip(self):
        expired = Authorization(
            owner="fictional-expired-test-owner",
            reference="SYNTHETIC-EXPIRED-NOT-CONSENT",
            valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
            valid_until=datetime(2021, 1, 1, tzinfo=timezone.utc),
        )
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({HOST}),
            explicit_networks=("198.51.100.0/24", "2001:db8::/32"),
        )
        for value in (HOST, "198.51.100.42", "https://[2001:db8::42]/"):
            with self.subTest(target_kind=value):
                decision = policy.decide(Target(value, expired))
                self.assertEqual(
                    (decision.allowed, decision.reason),
                    (False, ScopeReason.AUTHORIZATION_EXPIRED),
                )

    @staticmethod
    def _matrix_network_to_host_decisions():
        # Ten distinct malformed CIDRs x four canonical forms of one fictional
        # exact-match hostname. The loop fully materializes every source call.
        malformed = (
            "not-a-cidr",
            "198.51.100.0/33",
            "198.51.100.0/-1",
            "198.51.100.0/abc",
            "198.51.100.0/",
            "198.51.100.999/24",
            "2001:db8::/129",
            "2001:db8::/999",
            "2001:db8::/x",
            "",
        )
        forms = (
            HOST,
            "SECURITY.EXAMPLE.TEST",
            "https://security.example.test/alpha",
            "https://security.example.test/beta?x=1",
        )
        return [
            policy_with_bad_networks((bad,)).decide(
                Target(host_form, authorization=FAKE_AUTH)
            )
            for bad in malformed
            for host_form in forms
        ]

    @staticmethod
    def _matrix_host_to_network_decisions():
        # Six non-string host collection entries x three fictional
        # documentation-IP literals. No external assets or network I/O.
        malformed = (
            None, False, 17, 3.25, b"invalid-host", ("tuple",)
        )
        targets = (
            "198.51.100.42", "198.51.100.43", "198.51.100.44"
        )
        return [
            ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({bad}),
                explicit_networks=("198.51.100.0/24",),
            ).decide(Target(ip, authorization=FAKE_AUTH))
            for bad in malformed
            for ip in targets
        ]

    def test_matrix_witness_40_actual_network_to_host_allows(self):
        decisions = self._matrix_network_to_host_decisions()
        self.assertEqual(len(decisions), 40)
        for decision in decisions:
            self.assertEqual(
                (decision.allowed, decision.reason),
                (True, ScopeReason.EXPLICIT_HOST),
                "Only a real unsafe installed-source permit is a RED witness",
            )

    @unittest.expectedFailure
    def test_red_matrix_all_40_bad_network_to_host_admissions_must_deny(self):
        decisions = self._matrix_network_to_host_decisions()
        self.assertEqual(len(decisions), 40)
        self.assertEqual(sum(item.allowed for item in decisions), 0)

    def test_matrix_witness_18_actual_host_to_network_allows(self):
        decisions = self._matrix_host_to_network_decisions()
        self.assertEqual(len(decisions), 18)
        for decision in decisions:
            self.assertEqual(
                (decision.allowed, decision.reason),
                (True, ScopeReason.EXPLICIT_NETWORK),
                "Only a real unsafe installed-source permit is a RED witness",
            )

    @unittest.expectedFailure
    def test_red_matrix_all_18_bad_host_to_network_admissions_must_deny(self):
        decisions = self._matrix_host_to_network_decisions()
        self.assertEqual(len(decisions), 18)
        self.assertEqual(sum(item.allowed for item in decisions), 0)

    def test_expected_red_is_missing_denial_not_unrelated_exception(self):
        # A RED that crashes with TypeError/ValueError is NOT a valid security finding.
        # This deliberate incorrect expectation proves a normal assertion is needed.
        unsafe_decision = policy_with_bad_networks(("invalid-cidr",)).decide(
            Target(HOST, FAKE_AUTH)
        )
        self.assertTrue(unsafe_decision.allowed)
        with self.assertRaisesRegex(AssertionError, "True is not false"):
            self.assertFalse(unsafe_decision.allowed)


if __name__ == "__main__":
    unittest.main()
