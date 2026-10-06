import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ExplicitHostPolicyWhitespaceTests(unittest.TestCase):
    def test_whitespace_decorated_policy_entries_do_not_mint_host_authority(self):
        decorated_policy_entries = (
            " security.example.test",
            "security.example.test ",
            "\tsecurity.example.test",
            "security.example.test\n",
            "\nsecurity.example.test\t",
        )

        for policy_entry in decorated_policy_entries:
            with self.subTest(policy_entry=repr(policy_entry)):
                policy = ScopePolicy(
                    explicit_hosts=frozenset({policy_entry}),
                    require_authorization_for_public=False,
                )
                decision = policy.decide(Target("security.example.test"))

                self.assertFalse(decision.allowed)
                self.assertEqual(decision.normalized_host, "security.example.test")
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_target_side_whitespace_keeps_existing_normalization(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=False,
        )

        decision = policy.decide(Target("  security.example.test\t"))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "security.example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_plain_policy_entry_keeps_case_and_trailing_dot_canonical_match(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"SECURITY.EXAMPLE.TEST."}),
            require_authorization_for_public=False,
        )

        decision = policy.decide(Target("security.example.test"))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "security.example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)


if __name__ == "__main__":
    unittest.main()
