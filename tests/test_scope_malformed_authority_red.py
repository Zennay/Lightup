"""Fail-closed regression for malformed URL authorities; no network interaction."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class MalformedAuthorityTests(unittest.TestCase):
    def test_malformed_bracketed_host_never_raises_or_allows(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"example.test"}),
        )
        for candidate in (
            "http://[",
            "https://[::1",
            "https://[not-an-ip]/",
            "http://example.test:invalid/",
            "http://example.test:999999/",
        ):
            with self.subTest(candidate=candidate):
                decision = policy.decide(Target(candidate))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_malformed_port_cannot_reuse_an_existing_public_grant(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"example.test"}),
        )
        grant = Authorization(owner="fixture-owner", reference="fixture-grant")
        for candidate in (
            "https://example.test:invalid/path",
            "https://example.test:999999/path",
        ):
            with self.subTest(candidate=candidate):
                decision = policy.decide(Target(candidate, authorization=grant))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_valid_explicit_host_still_requires_grant(self):
        decision = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"example.test"}),
        ).decide(Target("https://example.test/path"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)


if __name__ == "__main__":
    unittest.main()
