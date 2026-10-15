"""Current-main, offline source acceptance for open scope issue #291.

The expected failures are real source defects; green unittest discovery is NOT a
claim that bare IPv6 identity or public authorization has been repaired.
"""
from __future__ import annotations

import ipaddress
import socket
import unittest
from datetime import datetime, timedelta, timezone
from contextlib import ExitStack
from unittest.mock import patch

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason

# RFC 3849 documentation-only IPv6 literals: never real target identities.
# All three collapse to an unrelated bare DNS hostname "2001" on current main.
DOC_IPV6 = (
    "2001:db8:1::1111",
    "2001:db8:2::2222",
    "2001:db8:3::3333",
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
            for literal in DOC_IPV6:
                result = ScopePolicy.normalize_host(literal)
                self.assertIn(result, (None, literal), (literal, result))

    @unittest.expectedFailure
    def test_current_main_truncated_explicit_hostname_must_not_admit_ipv6_red(self):
        """#291: an unrelated DNS label '2001' cannot admit synthetic bare IPv6."""
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2001"}),
            require_authorization_for_public=False,
        )
        with self.no_network():
            for literal in DOC_IPV6:
                decision = policy.decide(Target(literal))
                self.assertFalse(decision.allowed, (literal, decision))
                self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_current_main_attached_claim_cannot_rescue_truncated_host_red(self):
        """#291: attaching a fictional approval must not invent host membership."""
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2001"}),
            require_authorization_for_public=True,
        )
        with self.no_network():
            decision = policy.decide(Target(DOC_IPV6[0], authorization=SYNTHETIC_AUTH))
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_authorized_activation_must_not_mint_wrong_host_permit_red(self):
        """#291: the real production gate must reject the colliding bare IPv6."""
        gate = ActivationGate(
            ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"2001"}),
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
                    Target(DOC_IPV6[0], authorization=SYNTHETIC_AUTH),
                    "fixture-only-no-adapter",
                )

    def test_plan_and_lab_modes_reject_synthetic_host_collision(self):
        scope = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2001"}),
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
                        Target(DOC_IPV6[0], authorization=SYNTHETIC_AUTH),
                        "fixture-only-no-adapter",
                    )

    @unittest.expectedFailure
    def test_current_main_256_documentation_ipv6_scope_collisions_red(self):
        """Materialize every synthetic decision before asserting the source RED."""
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2001"}),
            require_authorization_for_public=True,
        )
        violations = []
        with self.no_network():
            for hextet in range(256):
                literal = str(ipaddress.IPv6Address(f"2001:db8:{hextet:x}::1"))
                decision = policy.decide(Target(literal, authorization=SYNTHETIC_AUTH))
                if (decision.allowed or
                        decision.normalized_host not in (None, literal)):
                    violations.append(hextet)
        self.assertEqual(
            violations, [],
            f"{len(violations)} synthetic documentation IPv6 identities misbound",
        )

    def test_256_bracketed_documentation_ipv6_never_match_unrelated_host(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2001"}),
            require_authorization_for_public=True,
        )
        with self.no_network():
            for hextet in range(256):
                literal = str(ipaddress.IPv6Address(f"2001:db8:{hextet:x}::1"))
                decision = policy.decide(Target("[" + literal + "]", authorization=SYNTHETIC_AUTH))
                self.assertFalse(decision.allowed, (hextet, decision))
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
                self.assertEqual(decision.normalized_host, literal)

    @unittest.expectedFailure
    def test_authorized_gate_must_not_mint_any_token_for_128_wrong_hosts_red(self):
        """Synthetic public-scope collision must be denied BEFORE token issuance."""
        gate = ActivationGate(
            ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"2001"}),
                require_authorization_for_public=True,
            ),
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="FIXTURE-ONLY",
            ),
        )
        wrong_identity_tokens = []
        with self.no_network(), patch(
            "lightup.activation.token_urlsafe",
            side_effect=lambda size: wrong_identity_tokens.append(size) or "FAKE-NON-LIVE-TOKEN",
        ):
            for hextet in range(128):
                literal = str(ipaddress.IPv6Address(f"2001:db8:{hextet:x}::beef"))
                try:
                    gate.issue(
                        Target(literal, authorization=SYNTHETIC_AUTH),
                        "fixture-only-no-adapter",
                    )
                except PermissionError:
                    continue
        self.assertEqual(
            wrong_identity_tokens, [],
            f"{len(wrong_identity_tokens)} synthetic wrong-host tokens minted",
        )

    def test_missing_or_expired_claim_never_mints_token_even_with_bad_host_normalization(self):
        """Negative controls: keep temporal checks strict before token generation."""
        now = datetime.now(timezone.utc)
        expired = Authorization(
            owner="offline-fixture-only",
            reference="not-a-real-approval",
            valid_until=now - timedelta(days=2),
        )
        future = Authorization(
            owner="offline-fixture-only",
            reference="not-a-real-approval",
            valid_from=now + timedelta(days=2),
        )
        gate = ActivationGate(
            ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"2001"}),
                require_authorization_for_public=True,
            ),
            ActivationPolicy(mode=ActivationMode.AUTHORIZED, activation_reference="FIXTURE-ONLY"),
        )
        with self.no_network(), patch(
            "lightup.activation.token_urlsafe",
            side_effect=AssertionError("token MUST NOT be minted"),
        ):
            for auth in (None, expired, future):
                with self.subTest(auth=auth):
                    with self.assertRaises(PermissionError):
                        gate.issue(
                            Target(DOC_IPV6[0], authorization=auth),
                            "fixture-only-no-adapter",
                        )

    def test_64_authorized_exact_ipv6_network_permits_preserve_full_target_identity(self):
        """Correct bracketed /128 controls for source-owner parser repair."""
        with self.no_network(), patch(
            "lightup.activation.token_urlsafe",
            return_value="FAKE-TEST-ONLY-NEVER-DEPLOY",
        ):
            for hextet in range(64):
                literal = str(ipaddress.IPv6Address(f"2001:db8:6:{hextet:x}::1"))
                other = str(ipaddress.IPv6Address(f"2001:db8:7:{hextet:x}::1"))
                policy = ScopePolicy(
                    allow_private_lab=False,
                    explicit_hosts=frozenset({"2001"}),
                    explicit_networks=(literal + "/128",),
                    require_authorization_for_public=True,
                )
                gate = ActivationGate(
                    policy,
                    ActivationPolicy(
                        mode=ActivationMode.AUTHORIZED,
                        activation_reference="FIXTURE-ONLY",
                    ),
                )
                permit = gate.issue(
                    Target("[" + literal + "]", authorization=SYNTHETIC_AUTH),
                    "fixture-only-no-adapter",
                )
                self.assertEqual(permit.target, literal)
                self.assertEqual(permit.capability_id, "fixture-only-no-adapter")
                self.assertEqual(permit.permit_id, "FAKE-TEST-ONLY-NEVER-DEPLOY")
                self.assertEqual(permit.mode, ActivationMode.AUTHORIZED)
                with self.assertRaises(PermissionError):
                    gate.issue(
                        Target("[" + other + "]", authorization=SYNTHETIC_AUTH),
                        "fixture-only-no-adapter",
                    )

    @unittest.expectedFailure
    def test_1024_bare_ipv6_lexical_variants_never_alias_dns_label_red(self):
        """Compact, upper, expanded and expanded-upper are identical IP identities."""
        bad = []
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2001"}),
            require_authorization_for_public=True,
        )
        with self.no_network():
            for suffix in range(256):
                ip = ipaddress.IPv6Address(f"2001:db8:5:{suffix:x}::4")
                for kind, literal in enumerate(
                    (str(ip), str(ip).upper(), ip.exploded, ip.exploded.upper())
                ):
                    decision = policy.decide(Target(literal, authorization=SYNTHETIC_AUTH))
                    exact = decision.normalized_host
                    try:
                        matched = exact is not None and ipaddress.IPv6Address(exact) == ip
                    except ValueError:
                        matched = False
                    if decision.allowed or (exact is not None and not matched):
                        bad.append((suffix, kind))
        self.assertEqual(
            bad, [],
            f"{len(bad)} synthetic bare IPv6 lexical forms misbound",
        )

    def test_1024_bracketed_ipv6_lexical_variants_preserve_identity_without_alias(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"2001"}),
            require_authorization_for_public=True,
        )
        with self.no_network():
            for suffix in range(256):
                ip = ipaddress.IPv6Address(f"2001:db8:5:{suffix:x}::4")
                for literal in (str(ip), str(ip).upper(), ip.exploded, ip.exploded.upper()):
                    decision = policy.decide(
                        Target("[" + literal + "]", authorization=SYNTHETIC_AUTH)
                    )
                    self.assertFalse(decision.allowed, (literal, decision))
                    self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
                    self.assertEqual(ipaddress.IPv6Address(decision.normalized_host), ip)

    def test_valid_bracketed_authority_remains_full_canonical_identity(self):
        with self.no_network():
            for literal in DOC_IPV6:
                self.assertEqual(ScopePolicy.normalize_host("[" + literal + "]"), literal)
                self.assertEqual(ScopePolicy.normalize_host("https://[" + literal + "]"), literal)

    def test_explicit_ipv6_network_matching_requires_current_claim(self):
        for literal in DOC_IPV6:
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
            "test_current_main_256_documentation_ipv6_scope_collisions_red":
                "256 synthetic documentation IPv6 identities misbound",
            "test_authorized_gate_must_not_mint_any_token_for_128_wrong_hosts_red":
                "128 synthetic wrong-host tokens minted",
            "test_1024_bare_ipv6_lexical_variants_never_alias_dns_label_red":
                "1024 synthetic bare IPv6 lexical forms misbound",
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
            explicit_hosts=frozenset({"2001"}),
            explicit_networks=("2001:db8:2::2222/128",),
            require_authorization_for_public=False,
        )
        with self.no_network():
            result = policy.decide(Target("[2001:db8:1::1111]"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
