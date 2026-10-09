"""Offline characterisation: URL control characters must not become authority.

These tests intentionally make no sockets, DNS requests or HTTP calls.
Legacy urllib.parse silently removes selected ASCII controls; XFAIL means
the scope gate currently DOES NOT satisfy a production denial requirement.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason

HOST = "authorized.example.test"
POLICY = ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset({HOST}))
AUTH = Authorization(owner="synthetic-not-verified", reference="FIXTURE-NOT-CONSENT")


class ControlCharacterScopeReference(unittest.TestCase):
    def test_canonical_authorized_hostname_control(self):
        result = POLICY.decide(Target("https://" + HOST + "/normal", authorization=AUTH))
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_HOST)

    def test_unknown_hostname_control(self):
        self.assertFalse(POLICY.decide(Target("https://unlisted.example.test/", authorization=AUTH)).allowed)

    def test_missing_authorization_control(self):
        result = POLICY.decide(Target("https://" + HOST + "/normal"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    @unittest.expectedFailure
    def test_newline_inside_authority_must_deny(self):
        self.assertFalse(POLICY.decide(Target("https://autho\nrized.example.test/", authorization=AUTH)).allowed)

    @unittest.expectedFailure
    def test_tab_inside_authority_must_deny(self):
        self.assertFalse(POLICY.decide(Target("https://autho\trized.example.test/", authorization=AUTH)).allowed)

    @unittest.expectedFailure
    def test_carriage_return_inside_authority_must_deny(self):
        self.assertFalse(POLICY.decide(Target("https://autho\rrized.example.test/", authorization=AUTH)).allowed)

    @unittest.expectedFailure
    def test_newline_inside_host_without_scheme_must_deny(self):
        self.assertFalse(POLICY.decide(Target("autho\nrized.example.test", authorization=AUTH)).allowed)

    @unittest.expectedFailure
    def test_tab_inside_host_without_scheme_must_deny(self):
        self.assertFalse(POLICY.decide(Target("autho\trized.example.test", authorization=AUTH)).allowed)

    def test_control_characters_do_not_allow_unlisted_hosts(self):
        for host in ("unlisted.example.test", "other.example.test"):
            for control in ("\n", "\r", "\t"):
                with self.subTest(host=host, control=repr(control)):
                    dirty = host.replace(".", control + ".", 1)
                    self.assertFalse(POLICY.decide(Target("https://" + dirty, authorization=AUTH)).allowed)


if __name__ == "__main__":
    unittest.main()
