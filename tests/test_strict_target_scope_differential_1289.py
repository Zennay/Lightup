"""Deterministic differential scope-admission checks for issue #1289.

This test never resolves DNS or contacts any service. Its randomized examples
are reproducible and have no link to real customer or public test targets.
"""
from __future__ import annotations

import random
import unittest
from datetime import datetime, timedelta, timezone
from itertools import product

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason
from lightup.strict_target_scope_optin import StrictTargetScopePolicy


class StrictTargetDifferential1289Tests(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(
            explicit_hosts=frozenset(("app.example.test",)),
            explicit_networks=("8.8.8.0/24",),
        )
        self.strict = StrictTargetScopePolicy(self.policy)
        self.authorization = Authorization(
            owner="synthetic",
            reference="OFFLINE-ONLY",
            valid_until=datetime.now(timezone.utc) + timedelta(days=1),
        )

    def assert_no_widening(self, literal):
        attempt = Target(literal, authorization=self.authorization)
        strict = self.strict.decide(attempt)
        self.assertIsInstance(strict.allowed, bool)
        if strict.allowed:
            # Current legacy parse of the submitted ORIGINAL text must also
            # admit it: lexical parsing is restrictive, not a grant.
            legacy = self.policy.decide(attempt)
            self.assertTrue(legacy.allowed, repr(literal))
            self.assertIn(strict.reason, (
                ScopeReason.LOOPBACK,
                ScopeReason.PRIVATE_LAB,
                ScopeReason.EXPLICIT_HOST,
                ScopeReason.EXPLICIT_NETWORK,
            ))
        return strict

    def test_seeded_malformed_authority_corpus_never_widens_scope(self):
        rng = random.Random(1289)
        alphabet = "abcdefxyz012789.:-_@[]/%?#+\\, \r\n\t"
        allowed = denied = 0
        for _ in range(900):
            raw = "".join(rng.choice(alphabet)
                          for _ in range(rng.randint(0, 48)))
            for prefix in ("", "http://", "https://"):
                decision = self.assert_no_widening(prefix + raw)
                allowed += bool(decision.allowed)
                denied += not decision.allowed
        self.assertGreater(denied, 1500)
        # Non-vacuous separate canonical cases below prove positive admission.

    def test_canonical_target_cross_product_retains_permission_monotonicity(self):
        hosts = ("localhost", "LOCALHOST.", "127.0.0.1",
                 "[::1]", "10.1.2.3", "app.example.test",
                 "8.8.8.8", "unlisted.example.test")
        ports = ("", ":80", ":443", ":65535", ":0", ":65536",
                 ":NaN", ":")
        prefixes = ("", "http://", "https://")
        accepted = rejected = 0
        for host, port, prefix in product(hosts, ports, prefixes):
            decision = self.assert_no_widening(prefix + host + port)
            accepted += bool(decision.allowed)
            rejected += not decision.allowed
        self.assertGreater(accepted, 30)
        self.assertGreater(rejected, 30)

    def test_control_prefix_suffix_and_encoded_authority_matrix(self):
        for host in ("localhost", "127.0.0.1", "[::1]",
                     "app.example.test", "8.8.8.8"):
            for bad in ("\n", "\r", "\t", "\x00", "\x7f"):
                for value in (host + bad, bad + host,
                              "http://" + host + bad,
                              "https://" + bad + host):
                    with self.subTest(value=repr(value)):
                        strict = self.strict.decide(
                            Target(value, authorization=self.authorization))
                        self.assertFalse(strict.allowed)
                        self.assertEqual(strict.reason, ScopeReason.INVALID_TARGET)
            for value in ("http://user@" + host,
                          "https://admin:secret@" + host,
                          "http://" + host + "%",
                          "http://" + host + "#frag"):
                with self.subTest(value=value):
                    strict = self.strict.decide(
                        Target(value, authorization=self.authorization))
                    self.assertFalse(strict.allowed)
                    self.assertEqual(strict.reason, ScopeReason.INVALID_TARGET)

    def test_input_length_and_type_are_conservatively_bounded(self):
        for value in ("x" * 2049, "http://" + "x" * 2049, " " * 2048,
                      "local" + "\n" * 3000):
            decision = self.strict.decide(Target(value))
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
        for invalid in (False, True, 7, 1.1, object()):
            decision = self.strict.decide(Target(invalid))
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_original_policy_still_controls_public_authorization(self):
        sample = "https://app.example.test:443/synthetic-only"
        without = self.strict.decide(Target(sample))
        self.assertFalse(without.allowed)
        self.assertEqual(without.reason, ScopeReason.AUTHORIZATION_MISSING)
        granted = self.strict.decide(
            Target(sample, authorization=self.authorization))
        self.assertTrue(granted.allowed)
        self.assertEqual(granted.reason, ScopeReason.EXPLICIT_HOST)
        unknown = self.strict.decide(
            Target("https://unknown.example.test", authorization=self.authorization))
        self.assertFalse(unknown.allowed)
        self.assertEqual(unknown.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
