"""Offline scope acceptance: URL query data cannot create target authority."""
import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class QueryNonAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"authorized.example.test"}),
            require_authorization_for_public=True,
        )
        self.authorization = Authorization(owner="offline-owner", reference="OFFLINE-APPROVAL")

    def test_hostname_in_query_does_not_override_actual_host(self):
        for value in (
            "https://outside.example.test/?host=authorized.example.test",
            "https://outside.example.test/?target=https%3A%2F%2Fauthorized.example.test",
            "https://outside.example.test/?redirect_uri=https://authorized.example.test/",
            "https://outside.example.test/?scope=authorized.example.test",
        ):
            with self.subTest(value=value):
                decision = self.policy.decide(Target(value, authorization=self.authorization))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.normalized_host, "outside.example.test")
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_approval_claim_in_query_cannot_replace_authorization_object(self):
        for value in (
            "https://authorized.example.test/?authorization=OFFLINE-APPROVAL",
            "https://authorized.example.test/?approved=true&risk=low",
            "https://authorized.example.test/?owner=offline-owner",
        ):
            with self.subTest(value=value):
                decision = self.policy.decide(Target(value))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_query_does_not_revoke_or_change_real_host_identity(self):
        decision = self.policy.decide(Target(
            "https://authorized.example.test/?host=outside.example.test",
            authorization=self.authorization,
        ))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "authorized.example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)


if __name__ == "__main__":
    unittest.main()
