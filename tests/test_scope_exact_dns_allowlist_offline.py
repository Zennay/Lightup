"""Offline regression for exact DNS allowlisting; no DNS lookup or network traffic."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ExactHostAdmissionTests(unittest.TestCase):
    def test_public_host_allowlist_has_no_implicit_subdomain_or_suffix_wildcard(self):
        grant = Authorization(owner="fixture", reference="FIXTURE-ONLY")
        policy = ScopePolicy(explicit_hosts=frozenset({"example.test"}))
        for value in ("api.example.test", "example.test.evil.test", "notexample.test"):
            with self.subTest(value=value):
                decision = policy.decide(Target(value, authorization=grant))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_url_authority_not_embedded_host_text_decides_allowlisting(self):
        grant = Authorization(owner="fixture", reference="FIXTURE-ONLY")
        policy = ScopePolicy(explicit_hosts=frozenset({"approved.example.test"}))
        for value in (
            "https://approved.example.test@unlisted.example.test/path",
            "https://unlisted.example.test/path/approved.example.test",
            "https://unlisted.example.test/?next=approved.example.test",
        ):
            with self.subTest(value=value):
                decision = policy.decide(Target(value, authorization=grant))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_canonical_host_variants_still_require_explicit_current_authorization(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"approved.example.test"}))
        for value in ("APPROVED.EXAMPLE.TEST", "https://approved.example.test./route"):
            with self.subTest(value=value):
                decision = policy.decide(Target(value))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)


if __name__ == "__main__":
    unittest.main()
