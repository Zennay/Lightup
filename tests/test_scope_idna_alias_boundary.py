import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeIdnaAliasBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.auth = Authorization(owner="example-owner", reference="AUTH-IDNA-001")

    def test_punycode_allowlist_does_not_authorize_unicode_alias(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"xn--bcher-kva.example"})
        )

        decision = policy.decide(
            Target("https://bücher.example/path", authorization=self.auth)
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "bücher.example")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_unicode_allowlist_does_not_authorize_punycode_alias(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"bücher.example"}))

        decision = policy.decide(
            Target("https://xn--bcher-kva.example/path", authorization=self.auth)
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "xn--bcher-kva.example")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_case_and_trailing_dot_normalize_within_same_unicode_identity(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"bücher.example"}))

        decision = policy.decide(
            Target("https://BÜCHER.EXAMPLE./status", authorization=self.auth)
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "bücher.example")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_unicode_dot_separator_does_not_inherit_ascii_host_authority(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"security.example.test"}))

        decision = policy.decide(
            Target("security。example。test", authorization=self.auth)
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "security。example。test")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_unknown_unicode_hostname_remains_out_of_scope(self):
        decision = ScopePolicy().decide(Target("δοκιμή.example"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "δοκιμή.example")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
