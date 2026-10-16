"""Seeded synthetic hostile-shape matrix for non-authorizing #1482 reviews.

These tests only construct Python objects. They never touch real targets,
network, subprocess, database, permits or operator/customer grants.
"""
import os
import random
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation_decision_cohort_review_1482 import review_decision_cohort
from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


HOSTS = (
    "localhost", "127.0.0.1", "::1", "10.2.3.4", "8.8.8.8",
    "public.example.test", "http://localhost/abc",
    "https://fake:pass@public.example.test/", "localhost..",
    "[::1", "x" * 513, "\u200bpublic.example.test", "",
    "bad\x00host", "192.0.2.1", "2001:db8::a", "%%%not_a_host",
)
FLAGS = (True, False, 0, 1, "yes", None)
REASONS = tuple(ScopeReason)


class OfflineCohortHostileMatrixTests(unittest.TestCase):
    def assert_no_authority(self, verdict):
        self.assertIn(verdict.status, ("HOLD", "REVIEW_ONLY"))
        self.assertFalse(verdict.authorizes_execution)
        self.assertFalse(verdict.authorizes_release)
        self.assertIn(verdict.inspected, (0, 1))

    def test_exhaustive_host_reason_allow_type_cross_product(self):
        for host in HOSTS:
            for reason in REASONS:
                for allowed in FLAGS:
                    verdict = review_decision_cohort(
                        ((ScopePolicy(), Target(host),
                          ScopeDecision(allowed, host, reason)),)
                    )
                    self.assert_no_authority(verdict)

    def test_seeded_2048_mixed_fields_never_authorize(self):
        rng = random.Random(1482)
        for _ in range(2048):
            host = rng.choice(HOSTS)
            normalized = rng.choice((host, None, "localhost", "other.example.test"))
            allowed = rng.choice(FLAGS)
            reason = rng.choice(REASONS)
            record = ScopeDecision(allowed, normalized, reason)
            verdict = review_decision_cohort(((ScopePolicy(), Target(host), record),))
            self.assert_no_authority(verdict)

    def test_typed_hostile_policy_values_denied_without_stringifying(self):
        class Secret:
            def __str__(self):
                raise AssertionError("must not stringify policy values")
        verdict = review_decision_cohort(
            ((ScopePolicy(explicit_hosts=frozenset({Secret()})),
              Target("localhost"),
              ScopeDecision(True, "localhost", ScopeReason.LOOPBACK)),)
        )
        self.assertEqual(verdict.reason, "invalid_policy_configuration")
        self.assert_no_authority(verdict)

    def test_tuple_subclass_iterator_side_effect_blocked(self):
        class HostileTuple(tuple):
            def __iter__(self):
                raise AssertionError("must not iterate")
        r = review_decision_cohort(HostileTuple((None,)))
        self.assertEqual(r.reason, "invalid_batch")
        self.assert_no_authority(r)

    def test_private_identifiers_are_never_reflected(self):
        secret = "synthetic-private-customer-token-123456"
        r = review_decision_cohort(
            ((ScopePolicy(), Target(secret),
              ScopeDecision(True, secret, ScopeReason.LOOPBACK)),)
        )
        self.assertEqual(r.status, "HOLD")
        self.assertNotIn(secret, repr(r))
        self.assert_no_authority(r)

    def test_no_dns_socket_or_process_during_seeded_mixed_review(self):
        import subprocess
        rng = random.Random(17)
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            for _ in range(256):
                host = rng.choice(HOSTS)
                r = review_decision_cohort(
                    ((ScopePolicy(), Target(host),
                      ScopeDecision(False, host, ScopeReason.OUT_OF_SCOPE)),)
                )
                self.assert_no_authority(r)

    def test_64_row_batch_never_leaks_partial_approval(self):
        policy = ScopePolicy()
        rows = tuple(
            (policy, Target("127.0.0." + str(i)),
             ScopeDecision(True, "127.0.0." + str(i), ScopeReason.LOOPBACK))
            for i in range(1, 64)
        )
        denied = (
            policy, Target("public.example.test"),
            ScopeDecision(True, "public.example.test", ScopeReason.LOOPBACK),
        )
        r = review_decision_cohort(rows + (denied,))
        self.assertEqual((r.status, r.inspected), ("HOLD", 0))
        self.assertFalse(r.authorizes_execution)
        self.assertFalse(r.authorizes_release)


if __name__ == "__main__":
    unittest.main()
