"""Offline regression: URL fragments cannot substitute for target-host authority."""
import unittest
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class FragmentNonAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"approved.example.test"}),
            require_authorization_for_public=True,
        )
        self.approval = Authorization(owner="offline-test", reference="OFFLINE-001")

    def test_allowlisted_name_only_in_fragment_is_not_authorized(self):
        for value in (
            "https://outside.example.test/#approved.example.test",
            "https://outside.example.test/path#https://approved.example.test",
            "https://outside.example.test/#@approved.example.test",
        ):
            with self.subTest(value=value):
                decision = self.policy.decide(Target(value, authorization=self.approval))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.normalized_host, "outside.example.test")
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_missing_approval_is_not_supplied_by_fragment(self):
        for value in (
            "https://approved.example.test/#authorization=OFFLINE-001",
            "https://approved.example.test/#approved=true",
        ):
            with self.subTest(value=value):
                decision = self.policy.decide(Target(value))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_real_approval_remains_required_and_fragment_inert(self):
        decision = self.policy.decide(Target(
            "https://approved.example.test/path#outside.example.test",
            authorization=self.approval,
        ))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "approved.example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)


if __name__ == "__main__":
    unittest.main()
