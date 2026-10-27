"""Offline negative controls: public scope selection is not permission to act.

This suite deliberately does not perform DNS resolution or make network calls.
"""
import unittest
from datetime import datetime, timedelta, timezone

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class PublicTargetNegativeControls(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"approved.example"}),
            explicit_networks=("203.0.113.0/24",),
            require_authorization_for_public=True,
        )

    def test_listed_public_hosts_and_ips_still_require_grant(self):
        for raw in ("approved.example", "https://approved.example/path", "203.0.113.9"):
            with self.subTest(raw=raw):
                decision = self.policy.decide(Target(raw))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_valid_grant_does_not_widen_asset_scope(self):
        grant = Authorization("owner", "ref")
        for raw in ("unlisted.example", "203.0.114.9"):
            with self.subTest(raw=raw):
                decision = self.policy.decide(Target(raw, authorization=grant))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_expired_or_future_grant_cannot_unlock_listed_target(self):
        now = datetime.now(timezone.utc)
        grants = (
            Authorization("owner", "expired", valid_until=now - timedelta(days=1)),
            Authorization("owner", "future", valid_from=now + timedelta(days=1)),
        )
        for grant in grants:
            for raw in ("approved.example", "203.0.113.9"):
                with self.subTest(grant=grant.reference, raw=raw):
                    decision = self.policy.decide(Target(raw, authorization=grant))
                    self.assertFalse(decision.allowed)
                    self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_labels_do_not_override_public_authorization(self):
        decision = self.policy.decide(Target(
            "approved.example", labels=("lab", "approved", "safe", "owner_verified")
        ))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_valid_grant_and_explicit_asset_both_required(self):
        grant = Authorization("owner", "current")
        for raw, reason in (
            ("approved.example", ScopeReason.EXPLICIT_HOST),
            ("203.0.113.9", ScopeReason.EXPLICIT_NETWORK),
        ):
            with self.subTest(raw=raw):
                decision = self.policy.decide(Target(raw, authorization=grant))
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, reason)

    def test_default_unlisted_public_target_is_denied(self):
        policy = ScopePolicy()
        decision = policy.decide(Target(
            "unknown.example", authorization=Authorization("owner", "ref")
        ))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
