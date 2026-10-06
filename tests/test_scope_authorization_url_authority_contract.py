import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeAuthorizationUrlAuthorityContractTests(unittest.TestCase):
    def setUp(self):
        self.authorization = Authorization(
            owner="example-owner",
            reference="AUTH-URL-AUTHORITY",
        )
        self.policy = ScopePolicy(
            explicit_hosts=frozenset({"security.example.test"})
        )

    def decide(self, value: str):
        return self.policy.decide(
            Target(value=value, authorization=self.authorization)
        )

    def test_port_path_query_and_fragment_do_not_change_authority_host(self):
        decision = self.decide(
            "https://security.example.test:8443/"
            "assessment/path?next=https://evil.invalid/#security.example.test"
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "security.example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_allowlisted_host_in_userinfo_cannot_authorize_destination(self):
        decision = self.decide(
            "https://security.example.test@evil.invalid/assessment"
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "evil.invalid")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_schemeless_userinfo_confusion_cannot_authorize_destination(self):
        decision = self.decide(
            "security.example.test@evil.invalid:443/assessment"
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "evil.invalid")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_allowlisted_host_in_query_cannot_authorize_destination(self):
        decision = self.decide(
            "https://evil.invalid/?next=https://security.example.test/"
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "evil.invalid")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_allowlisted_host_in_fragment_cannot_authorize_destination(self):
        decision = self.decide(
            "https://evil.invalid/#https://security.example.test/"
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "evil.invalid")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_allowlisted_host_as_parent_suffix_cannot_authorize_destination(self):
        decision = self.decide(
            "https://security.example.test.evil.invalid/"
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.normalized_host, "security.example.test.evil.invalid"
        )
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_subdomain_of_allowlisted_host_is_not_implicitly_authorized(self):
        decision = self.decide(
            "https://admin.security.example.test/"
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "admin.security.example.test")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_percent_encoded_userinfo_cannot_authorize_destination(self):
        decision = self.decide(
            "https://security.example.test%40display@evil.invalid/"
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "evil.invalid")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_localhost_lookalike_dns_name_is_not_loopback(self):
        decision = ScopePolicy().decide(
            Target("https://localhost.evil.invalid/")
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "localhost.evil.invalid")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_loopback_text_inside_dns_name_is_not_loopback(self):
        decision = ScopePolicy().decide(
            Target("https://127.0.0.1.evil.invalid/")
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "127.0.0.1.evil.invalid")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
