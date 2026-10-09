"""Offline regression contract for malformed IPv6 authority delimiters.

These are synthetic inputs. No DNS, HTTP, scanning, or grants are performed.
Expected failures describe the current production gap, not passing authorization.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class MalformedIpv6AuthorityContract(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset())

    def test_well_formed_unlisted_ipv6_is_denied_without_network(self):
        decision = self.policy.decide(Target("https://[2001:db8::1]/"))
        self.assertFalse(decision.allowed)

    @unittest.expectedFailure
    def test_unclosed_bracket_denied_instead_of_raising(self):
        decision = self.policy.decide(Target("https://[2001:db8::1/path"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    @unittest.expectedFailure
    def test_stray_closing_bracket_denied_instead_of_raising(self):
        decision = self.policy.decide(Target("https://2001:db8::1]/path"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    @unittest.expectedFailure
    def test_unbalanced_brackets_on_explicit_host_denied(self):
        policy = ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset({"authorized.example.test"}))
        decision = policy.decide(Target("https://[authorized.example.test/path"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)


if __name__ == "__main__":
    unittest.main()
