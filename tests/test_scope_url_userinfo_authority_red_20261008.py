"""Offline regression: URL userinfo must never confer scope authority.

These tests do not contact targets or activate capabilities. They intentionally
capture the unsafe boundary in the legacy ScopePolicy as a RED contract.
"""
import unittest

from lightup.models import Target
from lightup.scope import ScopePolicy


class ScopeUserinfoAuthorityBoundary(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy()

    def test_plain_loopback_remains_allowlisted(self):
        self.assertTrue(self.policy.decide(Target("http://localhost:8080/")).allowed)

    def test_userinfo_must_not_grant_loopback_authority(self):
        for value in (
            "http://attacker.example@localhost:8080/",
            "http://unknown.invalid@127.0.0.1:8080/",
            "http://outside.invalid@localhost/",
            "http://@localhost/",
            "http://user:secret@localhost/",
        ):
            with self.subTest(value=value):
                self.assertFalse(self.policy.decide(Target(value)).allowed)

    def test_userinfo_must_not_grant_private_lab_authority(self):
        for value in ("http://outside.invalid@10.0.0.2/", "http://outside.invalid@192.168.1.2/"):
            with self.subTest(value=value):
                self.assertFalse(self.policy.decide(Target(value)).allowed)

    def test_explicit_host_userinfo_cannot_inherit_allowlist(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"approved.example"}), require_authorization_for_public=False)
        self.assertTrue(policy.decide(Target("https://approved.example/")).allowed)
        self.assertFalse(policy.decide(Target("https://outside.invalid@approved.example/")).allowed)
        self.assertFalse(policy.decide(Target("https://@approved.example/")).allowed)

    def test_similar_public_hostname_is_not_loopback(self):
        self.assertFalse(self.policy.decide(Target("http://localhost.invalid/")).allowed)


if __name__ == "__main__":
    unittest.main()
