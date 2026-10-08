"""Offline scope decision regression matrix: no DNS, sockets or target calls."""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeDecisionMatrixTests(unittest.TestCase):
    def test_unlisted_public_targets_never_inherit_other_host_grant(self):
        grant = Authorization(owner="lab", reference="OFFLINE-MATRIX")
        policy = ScopePolicy(explicit_hosts=frozenset({"allowed.example.test"}))
        for value in ("unlisted.example.test", "allowed.example.test.evil.test", "8.8.8.8"):
            with self.subTest(value=value):
                result = policy.decide(Target(value, authorization=grant))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_explicit_host_requires_current_grant_even_if_canonicalized(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"allowed.example.test"}))
        expired = Authorization(owner="lab", reference="EXPIRED",
                                valid_until=datetime.now(timezone.utc) - timedelta(days=1))
        future = Authorization(owner="lab", reference="FUTURE",
                               valid_from=datetime.now(timezone.utc) + timedelta(days=1))
        for auth, reason in ((None, ScopeReason.AUTHORIZATION_MISSING),
                             (expired, ScopeReason.AUTHORIZATION_EXPIRED),
                             (future, ScopeReason.AUTHORIZATION_EXPIRED)):
            with self.subTest(reason=reason, auth=auth):
                result = policy.decide(Target("https://ALLOWED.EXAMPLE.TEST./offline", authorization=auth))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, reason)
                self.assertEqual(result.normalized_host, "allowed.example.test")

    def test_private_lab_disabled_does_not_authorize_private_addresses(self):
        policy = ScopePolicy(allow_private_lab=False)
        for value in ("10.2.3.4", "192.168.4.5", "169.254.1.2"):
            with self.subTest(value=value):
                result = policy.decide(Target(value))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_default_policy_preserves_loopback_but_denies_unknown_public(self):
        policy = ScopePolicy(allow_private_lab=False)
        for value in ("localhost", "127.0.0.1", "[::1]"):
            with self.subTest(value=value):
                self.assertEqual(policy.decide(Target(value)).reason, ScopeReason.LOOPBACK)
        self.assertFalse(policy.decide(Target("8.8.4.4")).allowed)


if __name__ == "__main__":
    unittest.main()
