"""Installed ScopePolicy percent-encoded host identity regression (#366).

Pure in-process synthetic assertions. This is NOT consent, a production source fix,
proof that a URL consumer uses the same host, or authority to contact a target.
The separate PR #1017 exercises an independent single-segment *reference* grammar;
these tests instead invoke the actual installed policy from the current checkout.
"""
from __future__ import annotations

import os
import socket
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


HOST = "security.example.test"  # reserved .test namespace; no network
CIDR = "192.0.2.0/24"  # RFC5737 documentation only, not a real target
IP = "192.0.2.7"


def _grant():
    return Authorization(
        owner="fictional-scope-owner",
        reference="LAB-SYNTHETIC-NOT-CONSENT",
        valid_from=datetime.now(timezone.utc) - timedelta(hours=1),
        valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
    )


class InstalledPercentEncodedHostScopeTests(unittest.TestCase):
    def setUp(self):
        self.grant = _grant()
        self.host_policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({HOST}),
        )
        self.network_policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(CIDR,),
        )

    def _deny_unlisted(self, policy, raw):
        decision = policy.decide(Target(raw, authorization=self.grant))
        self.assertFalse(decision.allowed, repr(raw))
        self.assertIn(
            decision.reason, (ScopeReason.OUT_OF_SCOPE, ScopeReason.INVALID_TARGET),
            repr(raw),
        )

    def test_actual_policy_does_not_decode_encoded_explicit_hostname(self):
        variants = (
            "security%2eexample%2etest", "security%2Eexample%2Etest",
            "security%252eexample%252etest",
            "https://security%2eexample%2etest/a",
            "https://security%2Eexample%2Etest:443/",
            "security.example%2etest",
            "sec%75rity.example.test",
        )
        for raw in variants:
            with self.subTest(raw=raw):
                self._deny_unlisted(self.host_policy, raw)

    def test_encoded_allowlisted_prefix_is_not_scope_membership(self):
        variants = (
            "security.example.test%2eattacker.test",
            "https://security.example.test%2eattacker.test/path",
            "security.example.test%252eattacker.test",
            "security.example.test%2f.attacker.test",
        )
        for raw in variants:
            with self.subTest(raw=raw):
                self._deny_unlisted(self.host_policy, raw)

    def test_encoded_loopback_aliases_never_gain_loopback_trust(self):
        variants = (
            "localhost%2e", "LOCALHOST%2E", "localhost%252e",
            "127%2e0%2e0%2e1", "127%2E0%2E0%2E1",
            "https://127%2e0%2e0%2e1:8443/",
            "http://local%68ost/",
            "%3a%3a1",
        )
        policy = ScopePolicy(allow_private_lab=False)
        for raw in variants:
            with self.subTest(raw=raw):
                self._deny_unlisted(policy, raw)

    def test_encoded_documentation_ipv4_never_matches_cidr(self):
        variants = (
            "192%2e0%2e2%2e7", "192%2E0%2E2%2E7",
            "https://192%2e0%2e2%2e7/",
            "192.0.2%2e7", "192%252e0%252e2%252e7",
            "192.0.2.7%2eattacker.test",
        )
        for raw in variants:
            with self.subTest(raw=raw):
                self._deny_unlisted(self.network_policy, raw)

    def test_unknown_encoded_identity_cannot_be_rescued_by_grant(self):
        # An attached Authorization never manufactures explicit membership.
        self._deny_unlisted(self.host_policy, "sec%75rity.example.test")
        self._deny_unlisted(self.network_policy, "192%2e0%2e2%2e7")

    def test_disabling_public_auth_does_not_allow_encoded_alias(self):
        policy = ScopePolicy(
            allow_private_lab=False, explicit_hosts=frozenset({HOST}),
            require_authorization_for_public=False,
        )
        self.assertFalse(policy.decide(Target("security%2eexample%2etest")).allowed)

    def test_unencoded_host_requires_current_authorization(self):
        missing = self.host_policy.decide(Target(HOST))
        self.assertFalse(missing.allowed)
        self.assertEqual(missing.reason, ScopeReason.AUTHORIZATION_MISSING)
        positive = self.host_policy.decide(Target("https://security.example.test/ok", self.grant))
        self.assertTrue(positive.allowed)
        self.assertEqual(positive.reason, ScopeReason.EXPLICIT_HOST)

    def test_unencoded_documentation_ip_retains_cidr_semantics(self):
        missing = self.network_policy.decide(Target(IP))
        self.assertFalse(missing.allowed)
        self.assertEqual(missing.reason, ScopeReason.AUTHORIZATION_MISSING)
        positive = self.network_policy.decide(Target(IP, self.grant))
        self.assertTrue(positive.allowed)
        self.assertEqual(positive.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_unencoded_loopback_retains_loopback_semantics(self):
        policy = ScopePolicy(allow_private_lab=False)
        for raw in ("localhost", "127.0.0.1", "http://[::1]/", "http://localhost:8080/"):
            with self.subTest(raw=raw):
                result = policy.decide(Target(raw))
                self.assertTrue(result.allowed)
                self.assertEqual(result.reason, ScopeReason.LOOPBACK)

    def test_encoded_forms_do_not_trigger_dns_or_network_io(self):
        def forbidden(*args, **kwargs):
            self.fail("scope policy unexpectedly attempted network access")
        with (
            patch.object(socket, "getaddrinfo", side_effect=forbidden),
            patch.object(socket, "create_connection", side_effect=forbidden),
            patch.object(socket, "socket", side_effect=forbidden),
        ):
            for raw in (
                "localhost%2e", "127%2e0%2e0%2e1",
                "security%2eexample%2etest", "192%2e0%2e2%2e7",
            ):
                with self.subTest(raw=raw):
                    self._deny_unlisted(self.host_policy, raw)

    def test_normalization_keeps_literal_percent_escape(self):
        for raw in ("security%2eexample%2etest", "localhost%2e", "127%2e0%2e0%2e1"):
            with self.subTest(raw=raw):
                normalized = ScopePolicy.normalize_host(raw)
                self.assertIsNotNone(normalized)
                self.assertIn("%", normalized)
                self.assertNotEqual(normalized, raw.replace("%2e", "."))


if __name__ == "__main__":
    unittest.main()
