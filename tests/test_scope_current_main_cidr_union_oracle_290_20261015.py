"""Issue #290: current-main offline CIDR union oracle and denial boundaries.

Tests only. Every IP is a string fixture: no socket, DNS, scanning,
ToolExecutor, target activation, or real authorization is performed.
"""
from __future__ import annotations

import itertools
import os
import sys
import unittest
from ipaddress import ip_address, ip_network
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


FAKE_AUTH = Authorization(owner="fictitious-matrix", reference="NOT-CUSTOMER-CONSENT")
NETWORKS_V4 = ("8.8.8.0/29", "8.8.8.4/30", "1.1.1.0/30")
NETWORKS_V6 = ("2606:4700:4700::/126", "2606:4700:4700::2/127")


def _policy(networks, *, require_auth=True):
    return ScopePolicy(
        allow_private_lab=False,
        explicit_hosts=frozenset(),
        explicit_networks=tuple(networks),
        require_authorization_for_public=require_auth,
    )


def _target(address, *, fake_auth=False):
    literal = str(address)
    if ip_address(literal).version == 6:
        literal = f"[{literal}]"
    return Target(literal, authorization=FAKE_AUTH if fake_auth else None)


def _oracle(address, cidrs):
    candidate = ip_address(str(address))
    return any(candidate in ip_network(spec, strict=False) for spec in cidrs)


class CurrentMainCIDRUnionOracleTests(unittest.TestCase):
    def test_ipv4_cidr_union_matches_independent_stdlib_oracle(self):
        # Include both interior, network/broadcast addresses and neighbors.
        fixtures = (
            [f"8.8.8.{i}" for i in range(0, 11)]
            + ["8.8.7.255", "8.8.9.0", "1.1.0.255"]
            + [f"1.1.1.{i}" for i in range(0, 7)]
        )
        policy = _policy(NETWORKS_V4)
        for literal in fixtures:
            inside = _oracle(literal, NETWORKS_V4)
            with self.subTest(address=literal, authorized=True):
                decision = policy.decide(_target(literal, fake_auth=True))
                self.assertIs(decision.allowed, inside)
                self.assertIs(decision.reason, ScopeReason.EXPLICIT_NETWORK
                              if inside else ScopeReason.OUT_OF_SCOPE)
            with self.subTest(address=literal, authorized=False):
                decision = policy.decide(_target(literal))
                self.assertIs(decision.allowed, False)
                self.assertIs(decision.reason, ScopeReason.AUTHORIZATION_MISSING
                              if inside else ScopeReason.OUT_OF_SCOPE)

    def test_ipv6_cidr_union_matches_oracle_with_bracketed_literal(self):
        fixtures = [f"2606:4700:4700::{i:x}" for i in range(0, 9)]
        fixtures += ["2606:4700:46ff:ffff:ffff:ffff:ffff:ffff",
                     "2606:4700:4701::"]
        policy = _policy(NETWORKS_V6)
        for literal in fixtures:
            inside = _oracle(literal, NETWORKS_V6)
            with self.subTest(address=literal):
                allowed = policy.decide(_target(literal, fake_auth=True))
                denied = policy.decide(_target(literal))
                self.assertIs(allowed.allowed, inside)
                self.assertIs(allowed.reason, ScopeReason.EXPLICIT_NETWORK
                              if inside else ScopeReason.OUT_OF_SCOPE)
                self.assertIs(denied.allowed, False)
                self.assertIs(denied.reason, ScopeReason.AUTHORIZATION_MISSING
                              if inside else ScopeReason.OUT_OF_SCOPE)

    def test_permuting_and_duplicating_networks_never_changes_membership(self):
        samples = ("8.8.8.0", "8.8.8.4", "8.8.8.7", "8.8.8.8",
                   "1.1.1.1", "1.1.1.4", "9.9.9.9")
        baseline = _policy(NETWORKS_V4)
        expected = [baseline.decide(_target(ip, fake_auth=True)) for ip in samples]
        for variation in itertools.permutations(NETWORKS_V4):
            for networks in (variation, variation + (variation[0],)):
                with self.subTest(networks=networks):
                    observed = [_policy(networks).decide(_target(ip, fake_auth=True))
                                for ip in samples]
                    self.assertEqual(observed, expected)
                    # Membership never implies consent.
                    for ip in samples:
                        self.assertIs(_policy(networks).decide(_target(ip)).allowed, False)

    def test_disabling_authorization_check_does_not_expand_cidr_union(self):
        public_only = _policy(("8.8.8.4/30",), require_auth=False)
        for ip in ("8.8.8.3", "8.8.8.4", "8.8.8.7", "8.8.8.8"):
            with self.subTest(ip=ip):
                decision = public_only.decide(_target(ip))
                expected = _oracle(ip, ("8.8.8.4/30",))
                self.assertIs(decision.allowed, expected)
                self.assertIs(decision.reason, ScopeReason.EXPLICIT_NETWORK
                              if expected else ScopeReason.OUT_OF_SCOPE)

    def test_mixed_ip_families_are_noninterchangeable(self):
        v4 = _policy(NETWORKS_V4)
        v6 = _policy(NETWORKS_V6)
        self.assertIs(v4.decide(_target("2606:4700:4700::1", fake_auth=True)).allowed, False)
        self.assertIs(v6.decide(_target("8.8.8.1", fake_auth=True)).allowed, False)

    def test_malformed_network_in_any_position_is_not_ignored(self):
        for networks in (("invalid-cidr", "8.8.8.0/29"),
                         ("8.8.8.0/29", "invalid-cidr")):
            with self.subTest(networks=networks):
                with self.assertRaises(ValueError):
                    _policy(networks).decide(_target("8.8.8.4", fake_auth=True))

    def test_no_network_process_or_input_mutation_on_disjoint_membership(self):
        networks = tuple(NETWORKS_V4)
        policy = _policy(networks)
        target = _target("9.9.9.9", fake_auth=True)
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch("socket.socket", side_effect=AssertionError("socket forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
            before = (target, target.value, target.authorization, policy)
            first = policy.decide(target)
            second = policy.decide(target)
        self.assertEqual(first, second)
        self.assertIs(first.allowed, False)
        self.assertIs(first.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual(networks, NETWORKS_V4)
        self.assertIs(target, before[0])
        self.assertEqual(target.value, before[1])
        self.assertIs(target.authorization, before[2])
        self.assertIs(policy, before[3])


if __name__ == "__main__":
    unittest.main()
