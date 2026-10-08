"""Offline RED contract: URI schemes must not be discarded when deciding scope."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class SchemeAdmissionContract(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(explicit_hosts=frozenset({"allowed.example.test"}), require_authorization_for_public=False)

    def test_unsupported_schemes_cannot_inherit_host_authority(self):
        for value in ("ftp://allowed.example.test/file", "file://allowed.example.test/etc/passwd", "javascript://allowed.example.test/path", "custom://allowed.example.test/path"):
            with self.subTest(value=value):
                decision = self.policy.decide(Target(value))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_unsupported_schemes_cannot_inherit_loopback_or_private_lab_shortcuts(self):
        policy = ScopePolicy()
        for value in ("ftp://localhost/fixture", "file://127.0.0.1/etc/passwd", "custom://10.1.2.3/path"):
            with self.subTest(value=value):
                decision = policy.decide(Target(value))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_supported_web_scheme_retains_existing_host_membership(self):
        for value in ("https://allowed.example.test/a", "http://allowed.example.test/b"):
            with self.subTest(value=value):
                decision = self.policy.decide(Target(value))
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_unknown_public_host_is_still_out_of_scope(self):
        decision = self.policy.decide(Target("https://unknown.example.test/a"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
