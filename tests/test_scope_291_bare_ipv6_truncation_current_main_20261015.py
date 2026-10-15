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

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
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

    @unittest.expectedFailure
    def test_authorized_activation_must_not_mint_wrong_host_permit_red(self):
        """#291: the real production gate must reject the colliding bare IPv6."""
        gate = ActivationGate(
            ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"2606"}),
                require_authorization_for_public=True,
            ),
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="FIXTURE-NOT-LIVE-APPROVAL",
            ),
        )
        with self.no_network():
            with self.assertRaises(PermissionError):
                gate.issue(
                    Target(PUBLIC_IPV6[0], authorization=SYNTHETIC_AUTH),
                    "fixture-only-no-adapter",
                )

    def test_plan_and_lab_modes_reject_synthetic_host_collision(self):
        scope = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2606"}),
            require_authorization_for_public=True,
        )
        for mode in (ActivationMode.PLAN_ONLY, ActivationMode.LAB_ONLY):
            with self.subTest(mode=mode):
                gate = ActivationGate(
                    scope,
                    ActivationPolicy(mode=mode, activation_reference="FIXTURE-NOT-LIVE-APPROVAL"),
                )
                with self.no_network(), self.assertRaises(PermissionError):
                    gate.issue(
                        Target(PUBLIC_IPV6[0], authorization=SYNTHETIC_AUTH),
                        "fixture-only-no-adapter",
                    )

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

    def test_expected_reds_have_exact_source_assertion_not_masked_runtime_error(self):
        """Unexpected green, DNS trap, TypeError or a crash must never masquerade as RED."""
        red_cases = {
            "test_current_main_bare_literal_never_normalizes_to_short_hostname_red":
                "not found in",
            "test_current_main_truncated_explicit_hostname_must_not_admit_ipv6_red":
                "True is not false",
            "test_current_main_attached_claim_cannot_rescue_truncated_host_red":
                "True is not false",
            "test_authorized_activation_must_not_mint_wrong_host_permit_red":
                "PermissionError not raised",
        }
        for name, expected_message in red_cases.items():
            with self.subTest(name=name):
                result = unittest.TestResult()
                ScopeIpv6NoTruncationAcceptance(name).run(result)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.failures, [])
                self.assertEqual(result.unexpectedSuccesses, [])
                self.assertEqual(len(result.expectedFailures), 1)
                traceback_text = result.expectedFailures[0][1]
                self.assertIn("AssertionError:", traceback_text)
                self.assertIn(expected_message, traceback_text)
                for forbidden in (
                    "DNS forbidden", "network forbidden", "sockets forbidden",
                    "TypeError:", "ValueError:", "AttributeError:",
                ):
                    self.assertNotIn(forbidden, traceback_text)

    def test_no_network_guards_are_active(self):
        with self.no_network():
            with self.assertRaisesRegex(AssertionError, "DNS forbidden"):
                socket.getaddrinfo("example.test", 443)
            with self.assertRaisesRegex(AssertionError, "sockets forbidden"):
                socket.socket()

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
