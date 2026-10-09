"""Offline contract: every HTTP redirect destination needs an independent scope check.

No HTTP requests, DNS resolution, scanning or target dispatch occurs here.
"""
import unittest
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
