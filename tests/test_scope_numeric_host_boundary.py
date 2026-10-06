import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeNumericHostBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.auth = Authorization(owner="example-owner", reference="AUTH-NUMERIC-001")

    def assert_out_of_scope(self, value: str) -> None:
        decision = ScopePolicy().decide(Target(value, authorization=self.auth))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, value.lower())
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_ipv4_shorthand_does_not_inherit_loopback_authority(self):
        self.assert_out_of_scope("127.1")

    def test_integer_ipv4_does_not_inherit_loopback_authority(self):
        self.assert_out_of_scope("2130706433")

    def test_hex_ipv4_does_not_inherit_loopback_authority(self):
        self.assert_out_of_scope("0x7f000001")

    def test_octal_like_ipv4_does_not_inherit_loopback_authority(self):
        self.assert_out_of_scope("0177.0.0.1")

    def test_zero_padded_ipv4_does_not_inherit_loopback_authority(self):
        self.assert_out_of_scope("127.000.000.001")

    def test_ambiguous_numeric_host_does_not_match_explicit_ipv4_network(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24",),
        )

        decision = policy.decide(
            Target("134744072", authorization=self.auth)
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "134744072")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_canonical_ipv4_literal_keeps_ip_classification(self):
        decision = ScopePolicy().decide(Target("127.0.0.1"))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "127.0.0.1")
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)


if __name__ == "__main__":
    unittest.main()
