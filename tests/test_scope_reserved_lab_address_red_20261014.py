"""Issue #1422: offline RED canaries for non-lab non-global IP classifications.

This is acceptance evidence ONLY: no DNS, sockets, target traffic, permits,
customer grants, activation, executor calls or deployment.
The source owner of #100 must implement the actual classification repair.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

# Permit direct execution via python -m unittest as well as project CI.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ReservedAddressNotPrivateLabRED(unittest.TestCase):
    """Each named expectedFailure is a known current-source security gap."""

    def setUp(self):
        self.policy = ScopePolicy(allow_private_lab=True)

    def assert_not_auto_admitted(self, address: str):
        result = self.policy.decide(Target(address))
        self.assertFalse(
            result.allowed,
            f"{address} must not be auto-authorized as a private lab",
        )
        self.assertNotEqual(
            result.reason,
            ScopeReason.PRIVATE_LAB,
            f"{address} is not a private-use lab address",
        )

    @unittest.expectedFailure
    def test_documentation_ipv4_test_net_one(self):
        self.assert_not_auto_admitted("192.0.2.1")

    @unittest.expectedFailure
    def test_documentation_ipv4_test_net_two(self):
        self.assert_not_auto_admitted("198.51.100.1")

    @unittest.expectedFailure
    def test_documentation_ipv4_test_net_three(self):
        self.assert_not_auto_admitted("203.0.113.1")

    @unittest.expectedFailure
    def test_benchmark_ipv4_not_lab(self):
        self.assert_not_auto_admitted("198.18.0.1")

    @unittest.expectedFailure
    def test_unspecified_ipv4_not_lab(self):
        self.assert_not_auto_admitted("0.0.0.0")

    @unittest.expectedFailure
    def test_broadcast_ipv4_not_lab(self):
        self.assert_not_auto_admitted("255.255.255.255")

    @unittest.expectedFailure
    def test_documentation_ipv6_not_lab(self):
        self.assert_not_auto_admitted("[2001:db8::1]")

    @unittest.expectedFailure
    def test_link_local_ipv4_not_implicitly_lab(self):
        self.assert_not_auto_admitted("169.254.1.1")

    def test_supported_loopback_and_private_use_controls(self):
        for address, reason in (
            ("127.0.0.1", ScopeReason.LOOPBACK),
            ("[::1]", ScopeReason.LOOPBACK),
            ("10.3.4.5", ScopeReason.PRIVATE_LAB),
            ("172.16.1.2", ScopeReason.PRIVATE_LAB),
            ("192.168.2.3", ScopeReason.PRIVATE_LAB),
            ("[fd00::1]", ScopeReason.PRIVATE_LAB),
        ):
            with self.subTest(address=address):
                result = self.policy.decide(Target(address))
                self.assertTrue(result.allowed, address)
                self.assertEqual(result.reason, reason, address)

    def test_private_lab_switch_off_denies_nonlab_and_rfc1918(self):
        locked = ScopePolicy(allow_private_lab=False)
        for address in (
            "192.0.2.1", "198.51.100.1", "203.0.113.1",
            "198.18.0.1", "0.0.0.0", "255.255.255.255",
            "[2001:db8::1]", "169.254.1.1",
            "10.3.4.5", "192.168.2.3", "[fd00::1]",
        ):
            with self.subTest(address=address):
                result = locked.decide(Target(address))
                self.assertFalse(result.allowed, address)

    def test_red_canaries_are_real_assertion_witnesses(self):
        """Guard against accidentally masking RED with import/runtime errors."""
        names = (
            "test_documentation_ipv4_test_net_one",
            "test_documentation_ipv4_test_net_two",
            "test_documentation_ipv4_test_net_three",
            "test_benchmark_ipv4_not_lab",
            "test_unspecified_ipv4_not_lab",
            "test_broadcast_ipv4_not_lab",
            "test_documentation_ipv6_not_lab",
            "test_link_local_ipv4_not_implicitly_lab",
        )
        suite = unittest.TestSuite(
            type(self)(name) for name in names
        )
        result = unittest.TestResult()
        suite.run(result)
        self.assertFalse(result.errors)
        self.assertFalse(result.failures)
        self.assertFalse(result.unexpectedSuccesses)
        self.assertEqual(len(result.expectedFailures), len(names))
        for _, traceback_text in result.expectedFailures:
            self.assertIn("AssertionError", traceback_text)


if __name__ == "__main__":
    unittest.main()
