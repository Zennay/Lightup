"""Offline regressions for the existing ScopePolicy public-target authorization gate.

No DNS, sockets, scanners or external targets are contacted.
"""
import unittest
from datetime import datetime, timedelta, timezone

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


PUBLIC = "8.8.8.8"
HOST = "example.test"


def grant(*, valid_from=None, valid_until=None):
    return Authorization(
        owner="synthetic-fixture-only",
        reference="not-real-consent",
        valid_from=valid_from,
        valid_until=valid_until,
    )


class PublicScopeAuthorizationWindowTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.ip_policy = ScopePolicy(
            allow_private_lab=False, explicit_networks=("8.8.8.8/32",)
        )
        self.host_policy = ScopePolicy(
            allow_private_lab=False, explicit_hosts=frozenset({HOST})
        )

    def test_public_allowlisted_ip_without_grant_is_denied(self):
        decision = self.ip_policy.decide(Target(PUBLIC))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_public_allowlisted_host_without_grant_is_denied(self):
        decision = self.host_policy.decide(Target(HOST))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_public_ip_expired_grant_is_denied(self):
        decision = self.ip_policy.decide(
            Target(PUBLIC, grant(valid_until=self.now - timedelta(days=1)))
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_public_host_not_yet_valid_grant_is_denied(self):
        decision = self.host_policy.decide(
            Target(HOST, grant(valid_from=self.now + timedelta(days=1)))
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_public_ip_current_synthetic_grant_matches_explicit_network(self):
        decision = self.ip_policy.decide(
            Target(
                PUBLIC,
                grant(
                    valid_from=self.now - timedelta(days=1),
                    valid_until=self.now + timedelta(days=1),
                ),
            )
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_public_host_current_synthetic_grant_matches_explicit_host(self):
        decision = self.host_policy.decide(
            Target(HOST, grant(valid_until=self.now + timedelta(days=1)))
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_unlisted_public_ip_is_denied_even_with_synthetic_grant(self):
        decision = self.ip_policy.decide(
            Target("9.9.9.9", grant(valid_until=self.now + timedelta(days=1)))
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_unlisted_public_host_is_denied_even_with_synthetic_grant(self):
        decision = self.host_policy.decide(
            Target("elsewhere.test", grant(valid_until=self.now + timedelta(days=1)))
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_authorized_host_does_not_authorize_userinfo_spoof(self):
        decision = self.host_policy.decide(
            Target(
                "https://example.test@elsewhere.test/path",
                grant(valid_until=self.now + timedelta(days=1)),
            )
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
