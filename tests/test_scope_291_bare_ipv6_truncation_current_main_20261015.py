"""Current-main, offline source acceptance for open scope issue #291.

The expected failures are real source defects; green unittest discovery is NOT a
claim that bare IPv6 identity or public authorization has been repaired.
"""
from __future__ import annotations

import ipaddress
import socket
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason

# These public synthetics have different literal identities from their leading
# hextet: the dangerous collision is when urlparse treats that hextet as a DNS
# hostname and a configured host allowlist permits the *other* identity.
PUBLIC_IPV6 = (
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
    "2a00:1450:4001::200e",
)
SYNTHETIC_AUTH = Authorization(
    owner="offline-fixture-only",
    reference="not-a-real-customer-approval",
)


class ScopeIpv6NoTruncationAcceptance(unittest.TestCase):
    def no_network(self):
        stack = ExitStack()
        stack.enter_context(patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")))
        stack.enter_context(patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")))
        stack.enter_context(patch.object(socket, "socket", side_effect=AssertionError("sockets forbidden")))
        return stack

    @unittest.expectedFailure
    def test_current_main_bare_literal_never_normalizes_to_short_hostname_red(self):
        """#291: expected RED until the actual source parser is corrected."""
        with self.no_network():
            for literal in PUBLIC_IPV6:
                result = ScopePolicy.normalize_host(literal)
                self.assertIn(result, (None, literal), (literal, result))

    @unittest.expectedFailure
    def test_current_main_truncated_explicit_hostname_must_not_admit_ipv6_red(self):
        """#291: a DNS allowlist for '2606' MUST NOT grant '2606:...::1111'."""
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2606", "2001", "2a00"}),
            require_authorization_for_public=False,
        )
        with self.no_network():
            for literal in PUBLIC_IPV6:
                decision = policy.decide(Target(literal))
                self.assertFalse(decision.allowed, (literal, decision))
                self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_current_main_attached_claim_cannot_rescue_truncated_host_red(self):
        """#291: attaching a fictional approval must not invent host membership."""
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2606"}),
            require_authorization_for_public=True,
        )
        with self.no_network():
            decision = policy.decide(Target(PUBLIC_IPV6[0], authorization=SYNTHETIC_AUTH))
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_valid_bracketed_authority_remains_full_canonical_identity(self):
        with self.no_network():
            for literal in PUBLIC_IPV6:
                self.assertEqual(ScopePolicy.normalize_host("[" + literal + "]"), literal)
                self.assertEqual(ScopePolicy.normalize_host("https://[" + literal + "]"), literal)

    def test_explicit_ipv6_network_matching_needs_matching_public_scope_and_claim(self):
        for literal in PUBLIC_IPV6:
            network = str(ipaddress.ip_network(literal + "/128"))
            policy = ScopePolicy(
                allow_private_lab=False,
                explicit_networks=(network,),
                require_authorization_for_public=True,
            )
            with self.no_network():
                missing = policy.decide(Target("[" + literal + "]"))
                present = policy.decide(Target("[" + literal + "]", authorization=SYNTHETIC_AUTH))
            self.assertFalse(missing.allowed)
            self.assertEqual(missing.reason, ScopeReason.AUTHORIZATION_MISSING)
            self.assertTrue(present.allowed)
            self.assertEqual(present.normalized_host, literal)
            self.assertEqual(present.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_unrelated_truncated_host_is_not_a_real_ipv6_network_membership(self):
        """A positive comparator prevents confusing host and CIDR authorization."""
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2606"}),
            explicit_networks=("2001:4860:4860::8888/128",),
            require_authorization_for_public=False,
        )
        with self.no_network():
            result = policy.decide(Target("[2606:4700:4700::1111]"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
