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
