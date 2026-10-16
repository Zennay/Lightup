"""Synthetic installed-source comparison for #1482 only; not a permission gate."""
import os
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation_fictional_source_differential_1482 import (
    review_fictional_installed_scope_decision,
)
from lightup.models import Authorization, Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


def policy(**kw):
    return ScopePolicy(allow_private_lab=False, **kw)


def original_pair(host, p=None):
    p = p if p is not None else policy()
    target = Target(host)
    return p, target, p.decide(target)


class FictionalSourceDifferentialTests(unittest.TestCase):
    def verdict(self, p, t, d):
        r = review_fictional_installed_scope_decision(p, t, d)
        self.assertIn(r.status, ("HOLD", "REVIEW_ONLY"))
        self.assertFalse(r.authorizes_execution)
        self.assertFalse(r.authorizes_release)
        return r

    def test_actual_loopback_source_matches_original_claim(self):
        p,t,d = original_pair("localhost")
        self.assertEqual(d.reason, ScopeReason.LOOPBACK)
        self.assertEqual(self.verdict(p,t,d).status, "REVIEW_ONLY")

    def test_actual_ipv4_loopback_source_matches(self):
        p,t,d = original_pair("127.0.0.1")
        self.assertEqual(self.verdict(p,t,d).status, "REVIEW_ONLY")

    def test_original_fictional_public_name_denial_matches(self):
        p,t,d = original_pair("review.example.test")
        self.assertEqual(d.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual(self.verdict(p,t,d).status, "REVIEW_ONLY")

    def test_explicit_fictional_name_without_auth_is_still_denied(self):
        p = policy(explicit_hosts=frozenset({"review.example.test"}))
        p,t,d = original_pair("review.example.test", p)
        self.assertEqual(d.reason, ScopeReason.AUTHORIZATION_MISSING)
        self.assertFalse(d.allowed)
        self.assertEqual(self.verdict(p,t,d).status, "REVIEW_ONLY")

    def test_forged_public_allow_does_not_match_source(self):
        p,t,_ = original_pair("review.example.test")
        fake = ScopeDecision(True, "review.example.test", ScopeReason.EXPLICIT_HOST)
        self.assertEqual(self.verdict(p,t,fake).reason, "source_claim_mismatch")

    def test_forged_normalized_host_does_not_match_source(self):
        p,t,d = original_pair("localhost")
        wrong = ScopeDecision(True, "other.example.test", ScopeReason.LOOPBACK)
        self.assertEqual(self.verdict(p,t,wrong).reason, "source_claim_mismatch")

    def test_raw_string_reason_is_hold(self):
        p,t,d = original_pair("localhost")
        wrong = ScopeDecision(True, "localhost", "loopback")
        self.assertEqual(self.verdict(p,t,wrong).reason, "source_claim_mismatch")

    def test_embedded_credentials_rejected_before_original_decide(self):
        p = policy()
        t = Target("https://u:p@review.example.test")
        d = ScopeDecision(False, "review.example.test", ScopeReason.OUT_OF_SCOPE)
        with patch.object(ScopePolicy, "decide", side_effect=AssertionError("called")):
            self.assertEqual(self.verdict(p,t,d).reason, "nonfictional_target")

    def test_malformed_double_dot_rejected_before_original_decide(self):
        p = policy()
        t = Target("review..example.test")
        d = ScopeDecision(False, "review..example.test", ScopeReason.OUT_OF_SCOPE)
        with patch.object(ScopePolicy, "decide", side_effect=AssertionError("called")):
            self.assertEqual(self.verdict(p,t,d).reason, "nonfictional_target")

    def test_uppercase_domain_rejected_before_source(self):
        p = policy()
        t = Target("REVIEW.example.test")
        d = ScopeDecision(False, "REVIEW.example.test", ScopeReason.OUT_OF_SCOPE)
        with patch.object(ScopePolicy, "decide", side_effect=AssertionError("called")):
            self.assertEqual(self.verdict(p,t,d).reason, "nonfictional_target")

    def test_target_with_authorization_is_rejected_without_checking_grants(self):
        p,t,d = original_pair("localhost")
        t = Target("localhost", Authorization("synthetic", "no-grant"))
        with patch.object(ScopePolicy, "decide", side_effect=AssertionError("called")):
            self.assertEqual(self.verdict(p,t,d).reason, "untrusted_target_metadata")

    def test_target_with_polymorphic_labels_rejected_without_equality(self):
        class DangerousLabels(list):
            def __eq__(self, _):
                raise AssertionError("never evaluate custom equality")
        p,t,d = original_pair("localhost")
        t = Target("localhost", labels=DangerousLabels())
        with patch.object(ScopePolicy, "decide", side_effect=AssertionError("called")):
            self.assertEqual(self.verdict(p,t,d).reason, "untrusted_target_metadata")

    def test_default_lab_enabled_policy_rejected_before_original_decide(self):
        p = ScopePolicy()
        t = Target("localhost")
        d = ScopeDecision(True, "localhost", ScopeReason.LOOPBACK)
        with patch.object(ScopePolicy, "decide", side_effect=AssertionError("called")):
            self.assertEqual(self.verdict(p,t,d).reason, "policy_outside_synthetic_lab")

    def test_nonempty_explicit_networks_rejected_without_decide(self):
        p = policy(explicit_networks=("127.0.0.0/8",))
        t = Target("localhost")
        d = ScopeDecision(True, "localhost", ScopeReason.LOOPBACK)
        with patch.object(ScopePolicy, "decide", side_effect=AssertionError("called")):
            self.assertEqual(self.verdict(p,t,d).reason, "policy_outside_synthetic_lab")

    def test_unknown_allowlist_name_rejected(self):
        p = policy(explicit_hosts=frozenset({"not-fictional.com"}))
        t = Target("localhost")
        d = ScopeDecision(True, "localhost", ScopeReason.LOOPBACK)
        self.assertEqual(self.verdict(p,t,d).reason, "policy_outside_synthetic_lab")

    def test_disabled_public_authorization_requirement_rejected(self):
        p = policy(require_authorization_for_public=False)
        t = Target("localhost")
        d = ScopeDecision(True, "localhost", ScopeReason.LOOPBACK)
        self.assertEqual(self.verdict(p,t,d).reason, "policy_outside_synthetic_lab")

    def test_policy_subclass_rejected(self):
        class Child(ScopePolicy):
            pass
        p = Child(allow_private_lab=False)
        t = Target("localhost")
        d = ScopeDecision(True, "localhost", ScopeReason.LOOPBACK)
        self.assertEqual(self.verdict(p,t,d).reason, "invalid_policy")

    def test_mocked_source_exception_is_generic_hold(self):
        p,t,d = original_pair("localhost")
        with patch.object(ScopePolicy, "decide", side_effect=RuntimeError("fake-token-secret")):
            r = self.verdict(p,t,d)
        self.assertEqual(r.reason, "source_review_error")
        self.assertNotIn("fake-token-secret", repr(r))

    def test_actual_original_source_probe_has_no_network_or_process(self):
        import subprocess
        p,t,d = original_pair("review.example.test")
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            r = self.verdict(p,t,d)
        self.assertEqual(r.status, "REVIEW_ONLY")

    def test_result_cannot_be_mutated_to_authorize(self):
        p,t,d = original_pair("localhost")
        r = self.verdict(p,t,d)
        with self.assertRaises((AttributeError, TypeError)):
            object.__setattr__(r, "authorizes_execution", True)
        self.assertFalse(r.authorizes_execution)


if __name__ == "__main__":
    unittest.main()
