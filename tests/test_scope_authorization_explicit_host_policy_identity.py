import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ExplicitHostPolicyIdentityTests(unittest.TestCase):
    def test_url_like_policy_entries_do_not_mint_host_authority(self):
        decorated_policy_entries = (
            "https://security.example.test",
            "operator@security.example.test",
            "security.example.test:443",
            "security.example.test/path",
            "security.example.test?next=/admin",
            "security.example.test#approved",
            "//security.example.test",
        )

        for policy_entry in decorated_policy_entries:
            with self.subTest(policy_entry=policy_entry):
                policy = ScopePolicy(
                    explicit_hosts=frozenset({policy_entry}),
                    require_authorization_for_public=False,
                )
                decision = policy.decide(Target("security.example.test"))

                self.assertFalse(decision.allowed)
                self.assertEqual(decision.normalized_host, "security.example.test")
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_target_url_normalization_does_not_parse_policy_entry(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"https://security.example.test"}),
            require_authorization_for_public=False,
        )

        decision = policy.decide(
            Target("https://security.example.test:8443/audit?mode=plan#scope")
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "security.example.test")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_plain_host_policy_entry_keeps_existing_canonical_match(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"SECURITY.EXAMPLE.TEST."}),
            require_authorization_for_public=False,
        )

        decision = policy.decide(
            Target("https://security.example.test:8443/audit?mode=plan#scope")
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "security.example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)


if __name__ == "__main__":
    unittest.main()
