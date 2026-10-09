"""Offline contract: every HTTP redirect destination needs an independent scope check.

No HTTP requests, DNS resolution, scanning or target dispatch occurs here.
"""
import unittest
from urllib.parse import urljoin
from datetime import datetime, timedelta, timezone

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class RedirectScopeReferenceTests(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"approved.example.test"}),
            explicit_networks=("8.8.8.8/32",),
        )
        self.grant = Authorization(owner="synthetic-test-only", reference="NOT_REAL_CONSENT")

    def decide(self, url, grant=None):
        return self.policy.decide(Target(url, authorization=grant))

    def test_approved_source_does_not_allow_unknown_redirect_host(self):
        self.assertTrue(self.decide("https://approved.example.test/start", self.grant).allowed)
        dest = self.decide("https://unlisted.example.test/redirect", self.grant)
        self.assertFalse(dest.allowed)
        self.assertEqual(dest.reason, ScopeReason.OUT_OF_SCOPE)

    def test_public_ip_redirect_cannot_inherit_hostname_scope(self):
        self.assertTrue(self.decide("https://approved.example.test/", self.grant).allowed)
        self.assertEqual(self.decide("http://1.1.1.1/", self.grant).reason, ScopeReason.OUT_OF_SCOPE)

    def test_redirect_to_allowlisted_ip_still_requires_own_authorization(self):
        dest = self.decide("https://8.8.8.8/", None)
        self.assertFalse(dest.allowed)
        self.assertEqual(dest.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_allowlisted_redirect_with_expired_authorization_denied(self):
        expired = Authorization(
            owner="synthetic-test-only",
            reference="EXPIRED-NOT-CONSENT",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        self.assertEqual(
            self.decide("https://approved.example.test/destination", expired).reason,
            ScopeReason.AUTHORIZATION_EXPIRED,
        )

    def test_url_userinfo_cannot_relabel_redirect_host(self):
        dest = self.decide("https://approved.example.test@unlisted.example.test/path", self.grant)
        self.assertFalse(dest.allowed)
        self.assertEqual(dest.normalized_host, "unlisted.example.test")

    def test_port_on_unknown_redirect_does_not_mint_scope(self):
        self.assertEqual(
            self.decide("https://unlisted.example.test:8443/path", self.grant).reason,
            ScopeReason.OUT_OF_SCOPE,
        )

    def test_redirect_to_explicit_host_without_grant_denied(self):
        self.assertEqual(
            self.decide("https://approved.example.test/another-hop").reason,
            ScopeReason.AUTHORIZATION_MISSING,
        )

    def test_disabling_authorization_does_not_expand_redirect_allowlist(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"approved.example.test"}),
            require_authorization_for_public=False,
        )
        self.assertFalse(policy.decide(Target("https://unlisted.example.test/")).allowed)

    def test_allowlisted_destination_future_grant_is_not_current(self):
        future = Authorization(
            owner="synthetic-test-only",
            reference="FUTURE-NOT-CONSENT",
            valid_from=datetime.now(timezone.utc) + timedelta(days=1),
        )
        decision = self.decide("https://approved.example.test/next", future)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_each_hop_requires_its_own_current_grant(self):
        hops = [
            ("https://approved.example.test/start", self.grant),
            ("https://approved.example.test/next", None),
        ]
        outcomes = [self.decide(url, grant) for url, grant in hops]
        self.assertEqual([item.allowed for item in outcomes], [True, False])
        self.assertEqual(outcomes[-1].reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_unlisted_public_destination_stays_denied_with_new_grant(self):
        different_grant = Authorization(owner="another-synthetic-owner", reference="NOT-CONSENT-2")
        self.assertEqual(
            self.decide("https://outside.example.test/", different_grant).reason,
            ScopeReason.OUT_OF_SCOPE,
        )

    def test_same_explicit_host_with_case_and_trailing_dot_remains_in_scope(self):
        decision = self.decide("https://APPROVED.EXAMPLE.TEST./next", self.grant)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)
        self.assertEqual(decision.normalized_host, "approved.example.test")

    def test_explicit_network_destination_with_current_grant(self):
        decision = self.decide("https://8.8.8.8/next", self.grant)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_adjacent_ip_outside_exact_allowlist_remains_denied(self):
        self.assertEqual(
            self.decide("https://8.8.8.9/next", self.grant).reason,
            ScopeReason.OUT_OF_SCOPE,
        )

    def test_public_redirect_does_not_inherit_private_lab_allowance(self):
        policy = ScopePolicy(allow_private_lab=True)
        self.assertTrue(policy.decide(Target("http://127.0.0.1/start")).allowed)
        dest = policy.decide(Target("https://unlisted.example.test/next", authorization=self.grant))
        self.assertFalse(dest.allowed)
        self.assertEqual(dest.reason, ScopeReason.OUT_OF_SCOPE)

    def test_empty_redirect_target_is_invalid_even_with_authorization(self):
        decision = self.decide("", self.grant)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_approved_host_custom_port_still_requires_authorization(self):
        decision = self.decide("https://approved.example.test:8443/next")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_unknown_host_switching_from_https_to_http_remains_denied(self):
        self.assertTrue(self.decide("https://approved.example.test/start", self.grant).allowed)
        decision = self.decide("http://unlisted.example.test/next", self.grant)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_relative_redirect_is_checked_against_resolved_origin(self):
        source = "https://approved.example.test/start"
        destination = urljoin(source, "../next")
        self.assertEqual(destination, "https://approved.example.test/next")
        self.assertEqual(
            self.decide(destination).reason,
            ScopeReason.AUTHORIZATION_MISSING,
        )

    def test_network_path_redirect_must_check_new_host(self):
        source = "https://approved.example.test/start"
        destination = urljoin(source, "//outside.example.test/next")
        self.assertEqual(
            self.decide(destination, self.grant).reason,
            ScopeReason.OUT_OF_SCOPE,
        )

    def test_absolute_redirect_to_other_port_requires_fresh_gate(self):
        source = "https://approved.example.test/start"
        destination = urljoin(source, "https://approved.example.test:9443/next")
        self.assertEqual(
            self.decide(destination).reason,
            ScopeReason.AUTHORIZATION_MISSING,
        )

    def test_redirect_chain_stops_at_first_denied_hop(self):
        hops = [
            "https://approved.example.test/first",
            "https://outside.example.test/denied",
            "https://approved.example.test/must-not-reach",
        ]
        visited = []
        for hop in hops:
            decision = self.decide(hop, self.grant)
            visited.append((hop, decision.allowed))
            if not decision.allowed:
                break
        self.assertEqual(visited, [
            (hops[0], True),
            (hops[1], False),
        ])

    def test_fragment_redirect_to_unlisted_host_still_denied(self):
        source = "https://approved.example.test/start"
        destination = urljoin(source, "//outside.example.test/path#fragment")
        self.assertEqual(self.decide(destination, self.grant).reason, ScopeReason.OUT_OF_SCOPE)

    def test_query_redirect_to_unlisted_host_still_denied(self):
        source = "https://approved.example.test/start"
        destination = urljoin(source, "https://outside.example.test/path?next=approved.example.test")
        self.assertEqual(self.decide(destination, self.grant).reason, ScopeReason.OUT_OF_SCOPE)

    def test_same_host_https_to_http_downgrade_is_not_blocked_by_legacy_scope(self):
        # Gap characterization, NOT a safe redirect-dispatch approval:
        # ScopePolicy is host-only and does not enforce scheme transitions.
        source = "https://approved.example.test/start"
        destination = urljoin(source, "http://approved.example.test/next")
        self.assertTrue(self.decide(source, self.grant).allowed)
        self.assertTrue(self.decide(destination, self.grant).allowed)

    def test_same_host_port_transition_is_not_blocked_by_legacy_scope(self):
        # The HTTP adapter must enforce separately approved ports before I/O.
        source = "https://approved.example.test/start"
        destination = urljoin(source, "https://approved.example.test:9443/next")
        self.assertTrue(self.decide(source, self.grant).allowed)
        self.assertTrue(self.decide(destination, self.grant).allowed)

    def test_unsupported_scheme_is_not_rejected_by_legacy_host_scope(self):
        # Characterization: URL scheme validation belongs to the dispatch layer.
        decision = self.decide("ftp://approved.example.test/resource", self.grant)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_scheme_relative_authorized_host_still_needs_grant(self):
        resolved = urljoin("https://outside.example.test/start", "//approved.example.test/path")
        decision = self.decide(resolved)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_redirect_with_mixed_case_unlisted_host_is_denied(self):
        decision = self.decide("https://OuTsIdE.ExAmPlE.TeSt/next", self.grant)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_explicit_ipv4_redirect_with_future_grant_is_denied(self):
        future = Authorization(
            owner="synthetic-test-only",
            reference="FUTURE-IP-NOT-CONSENT",
            valid_from=datetime.now(timezone.utc) + timedelta(days=1),
        )
        decision = self.decide("https://8.8.8.8/next", future)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_redirect_to_public_ip_with_expired_grant_is_denied(self):
        expired = Authorization(
            owner="synthetic-test-only",
            reference="EXPIRED-IP-NOT-CONSENT",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        decision = self.decide("https://8.8.8.8/next", expired)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_redirect_to_allowed_host_with_expired_grant_stops_chain(self):
        expired = Authorization(
            owner="synthetic-test-only",
            reference="EXPIRED-HOP-NOT-CONSENT",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        hops = [
            ("https://approved.example.test/start", self.grant),
            ("https://approved.example.test/expired", expired),
            ("https://approved.example.test/never-reached", self.grant),
        ]
        visited = []
        for url, grant in hops:
            result = self.decide(url, grant)
            visited.append(result.reason)
            if not result.allowed:
                break
        self.assertEqual(visited, [ScopeReason.EXPLICIT_HOST, ScopeReason.AUTHORIZATION_EXPIRED])

    def test_ipv6_public_destination_outside_allowlist_is_denied(self):
        decision = self.decide("https://[2606:4700:4700::1111]/", self.grant)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_encoded_allowed_hostname_in_path_does_not_authorize_destination(self):
        decision = self.decide(
            "https://outside.example.test/%61pproved.example.test/next",
            self.grant,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_ipv6_bracketed_redirect_with_explicit_network_requires_grant(self):
        policy = ScopePolicy(allow_private_lab=False, explicit_networks=("2606:4700:4700::1111/128",))
        decision = policy.decide(Target("https://[2606:4700:4700::1111]/"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_ipv6_bracketed_redirect_explicit_network_with_grant(self):
        policy = ScopePolicy(allow_private_lab=False, explicit_networks=("2606:4700:4700::1111/128",))
        decision = policy.decide(Target("https://[2606:4700:4700::1111]/", authorization=self.grant))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_ipv6_explicit_network_rejects_adjacent_address(self):
        policy = ScopePolicy(allow_private_lab=False, explicit_networks=("2606:4700:4700::1111/128",))
        decision = policy.decide(Target("https://[2606:4700:4700::1112]/", authorization=self.grant))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_ipv6_explicit_network_rejects_expired_grant(self):
        policy = ScopePolicy(allow_private_lab=False, explicit_networks=("2606:4700:4700::1111/128",))
        expired = Authorization(owner="synthetic-test-only", reference="EXPIRED-IPV6-NOT-CONSENT",
                                valid_until=datetime.now(timezone.utc) - timedelta(days=1))
        decision = policy.decide(Target("https://[2606:4700:4700::1111]/", authorization=expired))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_each_redirect_hop_rechecks_target_identity(self):
        hops = [
            "https://approved.example.test/start",
            "https://approved.example.test/step-two",
            "https://unlisted.example.test/final",
        ]
        results = [self.decide(url, self.grant) for url in hops]
        self.assertEqual([result.allowed for result in results], [True, True, False])


if __name__ == "__main__":
    unittest.main()
