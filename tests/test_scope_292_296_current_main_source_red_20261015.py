"""Current-main, *expected RED* contracts for open scope issues #292 and #296.

Test inputs are synthetic and evaluated only in memory. A fixture Authorization
is not real customer consent. Do not use these tests as a grant/scan permit.
The installed source currently violates the sixteen expected-failure cases; an
unexpectedSuccess means the source changed and this suite must be promoted to
ordinary passing tests by the production owner before release.
"""
from __future__ import annotations

import os
import sys
import unittest
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


_SYNTHETIC_AUTH = Authorization(owner="offline-test-only", reference="NOT-CUSTOMER-CONSENT")


class _NetworkStr(str):
    """Runtime subclass: annotations do not enforce an exact built-in str."""


class ExplicitNetworkSourceRed292296(unittest.TestCase):
    """A deny result OR a rejected invalid configuration is fail closed."""

    def _review(self, declaration: object, target: str):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(declaration,),
            require_authorization_for_public=True,
        )
        try:
            return policy.decide(Target(target, authorization=_SYNTHETIC_AUTH))
        except (TypeError, ValueError):
            return None  # Rejected configuration; never a grant.

    def _assert_rejected(self, declaration: object, target: str):
        result = self._review(declaration, target)
        if result is not None:
            self.assertFalse(result.allowed, "invalid network declaration minted scope authority")

    @unittest.expectedFailure
    def test_292_integer_must_not_create_ipv4_host_authority(self):
        self._assert_rejected(134744072, "8.8.8.8")

    @unittest.expectedFailure
    def test_292_raw_bytes_must_not_create_ipv4_host_authority(self):
        self._assert_rejected(b"\x08\x08\x08\x08", "8.8.8.8")

    @unittest.expectedFailure
    def test_292_boolean_must_not_create_ipv4_host_authority(self):
        self._assert_rejected(True, "0.0.0.1")

    @unittest.expectedFailure
    def test_292_string_subclass_must_not_create_network_authority(self):
        self._assert_rejected(_NetworkStr("8.8.8.0/24"), "8.8.8.9")

    @unittest.expectedFailure
    def test_296_ipv4_host_bits_must_not_widen_scope(self):
        self._assert_rejected("8.8.8.8/24", "8.8.8.9")

    @unittest.expectedFailure
    def test_296_ipv6_host_bits_must_not_widen_scope(self):
        self._assert_rejected("2001:4860:4860::8888/64", "[2001:4860:4860::8844]")

    @unittest.expectedFailure
    def test_292_ipv4_address_object_must_not_mint_explicit_scope(self):
        self._assert_rejected(IPv4Address("8.8.8.8"), "8.8.8.8")

    @unittest.expectedFailure
    def test_292_ipv4_network_object_must_not_mint_explicit_scope(self):
        self._assert_rejected(IPv4Network("8.8.8.8/32"), "8.8.8.8")

    @unittest.expectedFailure
    def test_292_ipv6_address_object_must_not_mint_explicit_scope(self):
        self._assert_rejected(IPv6Address("2001:4860:4860::8888"), "[2001:4860:4860::8888]")

    @unittest.expectedFailure
    def test_296_dotted_netmask_host_bits_must_not_widen_scope(self):
        self._assert_rejected("8.8.8.9/255.255.255.0", "8.8.8.10")

    @unittest.expectedFailure
    def test_292_ipv6_network_object_must_not_mint_explicit_scope(self):
        self._assert_rejected(
            IPv6Network("2001:4860:4860::8888/128"),
            "[2001:4860:4860::8888]",
        )

    @unittest.expectedFailure
    def test_296_bare_ipv4_host_must_require_explicit_32(self):
        self._assert_rejected("8.8.8.8", "8.8.8.8")

    @unittest.expectedFailure
    def test_296_bare_ipv6_host_must_require_explicit_128(self):
        self._assert_rejected("2001:4860:4860::8888", "[2001:4860:4860::8888]")

    @unittest.expectedFailure
    def test_296_dotted_prefix_mask_is_not_canonical_cidr(self):
        self._assert_rejected("8.8.8.0/255.255.255.0", "8.8.8.9")

    @unittest.expectedFailure
    def test_296_noncanonical_ipv6_network_text_is_not_canonical_cidr(self):
        self._assert_rejected("2001:4860:4860:0000::/64", "[2001:4860:4860::8888]")

    @unittest.expectedFailure
    def test_296_noncanonical_dotted_host_mask_must_require_32(self):
        self._assert_rejected("8.8.8.8/255.255.255.255", "8.8.8.8")

    def test_292_bytearray_is_never_permission(self):
        self._assert_rejected(bytearray(b"\x08\x08\x08\x08"), "8.8.8.8")

    def test_292_none_is_never_permission(self):
        self._assert_rejected(None, "8.8.8.8")

    def test_292_malformed_string_is_never_permission(self):
        self._assert_rejected("not-a-network", "8.8.8.8")

    def test_296_canonical_ipv4_network_preserved(self):
        result = self._review("8.8.8.0/24", "8.8.8.9")
        self.assertIsNotNone(result)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_296_canonical_ipv4_single_host_preserved(self):
        result = self._review("8.8.8.8/32", "8.8.8.8")
        self.assertIsNotNone(result)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_NETWORK)
        self._assert_rejected("8.8.8.8/32", "8.8.8.9")

    def test_296_canonical_ipv6_single_host_preserved(self):
        result = self._review("2001:4860:4860::8888/128", "[2001:4860:4860::8888]")
        self.assertIsNotNone(result)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_NETWORK)
        self._assert_rejected("2001:4860:4860::8888/128", "[2001:4860:4860::8844]")

    def test_296_canonical_ipv6_network_preserved(self):
        result = self._review("2001:4860:4860::/64", "[2001:4860:4860::8888]")
        self.assertIsNotNone(result)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_NETWORK)
        self._assert_rejected("2001:4860:4860::/64", "8.8.8.8")

    def test_empty_explicit_network_is_never_permission(self):
        self._assert_rejected("", "8.8.8.8")

    def test_malformed_ipv4_mask_is_never_permission(self):
        self._assert_rejected("8.8.8.0/33", "8.8.8.9")

    def test_explicit_public_network_needs_authorization(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )
        result = policy.decide(Target("8.8.8.9"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_sixteen_expected_reds_are_real_assertions_not_masked_errors(self):
        names = (
            "test_292_integer_must_not_create_ipv4_host_authority",
            "test_292_raw_bytes_must_not_create_ipv4_host_authority",
            "test_292_boolean_must_not_create_ipv4_host_authority",
            "test_292_string_subclass_must_not_create_network_authority",
            "test_296_ipv4_host_bits_must_not_widen_scope",
            "test_296_ipv6_host_bits_must_not_widen_scope",
            "test_292_ipv4_address_object_must_not_mint_explicit_scope",
            "test_292_ipv4_network_object_must_not_mint_explicit_scope",
            "test_292_ipv6_address_object_must_not_mint_explicit_scope",
            "test_296_dotted_netmask_host_bits_must_not_widen_scope",
            "test_292_ipv6_network_object_must_not_mint_explicit_scope",
            "test_296_bare_ipv4_host_must_require_explicit_32",
            "test_296_bare_ipv6_host_must_require_explicit_128",
            "test_296_dotted_prefix_mask_is_not_canonical_cidr",
            "test_296_noncanonical_ipv6_network_text_is_not_canonical_cidr",
            "test_296_noncanonical_dotted_host_mask_must_require_32",
        )
        proof = unittest.TestResult()
        # A red witness that performs target I/O is not valid evidence:
        # prohibit networking and new subprocesses throughout all 16 replays.
        with (
            patch("socket.socket", side_effect=AssertionError("network forbidden")),
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")),
            patch("subprocess.Popen", side_effect=AssertionError("process forbidden")),
            patch("os.system", side_effect=AssertionError("system command forbidden")),
        ):
            for name in names:
                type(self)(name).run(proof)
        self.assertEqual(proof.testsRun, len(names))
        self.assertEqual(proof.failures, [])
        self.assertEqual(proof.errors, [])
        self.assertEqual(proof.unexpectedSuccesses, [])
        self.assertEqual(len(proof.expectedFailures), len(names))
        for case, trace in proof.expectedFailures:
            self.assertIn(case._testMethodName, names)
            self.assertIn("AssertionError", trace)
            self.assertIn("invalid network declaration minted scope authority", trace)

    def test_offline_decisions_make_no_network_or_process_calls(self):
        with (
            patch("socket.socket", side_effect=AssertionError("network forbidden")),
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")),
            patch("subprocess.Popen", side_effect=AssertionError("process forbidden")),
        ):
            self.test_296_canonical_ipv4_network_preserved()
            self.test_292_malformed_string_is_never_permission()
            self.test_explicit_public_network_needs_authorization()


if __name__ == "__main__":
    unittest.main()
