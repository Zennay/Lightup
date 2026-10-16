"""#1482: independent synthetic LAB binding reference, never permit issuance."""
import os
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationMode, ActivationPolicy
from lightup.activation_lab_binding_reference_1482 import review_lab_binding
from lightup.models import Authorization, Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


def policy(**kwargs):
    return ScopePolicy(allow_private_lab=False, **kwargs)


def lab(ref="SYNTHETIC_LAB"):
    return ActivationPolicy(ActivationMode.LAB_ONLY, ref)


def run(host="localhost", *, p=None, a=None, t=None, decision=None):
    p = p if p is not None else policy()
    a = a if a is not None else lab()
    t = t if t is not None else Target(host)
    decision = decision if decision is not None else p.decide(t)
    return review_lab_binding(p, a, t, decision)


class LabBindingReferenceTests(unittest.TestCase):
    def assert_hold(self, result, reason=None):
        self.assertEqual(result.status, "HOLD")
        if reason is not None:
            self.assertEqual(result.reason, reason)
        self.assertFalse(result.authorizes_execution)
        self.assertFalse(result.authorizes_release)

    def assert_review(self, result):
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertFalse(result.authorizes_execution)
        self.assertFalse(result.authorizes_release)

    def test_localhost_matches_trusted_reference(self):
        self.assert_review(run("localhost"))

    def test_loopback_ipv4_matches_trusted_reference(self):
        self.assert_review(run("127.0.0.1"))

    def test_fictional_public_out_of_scope_matches_deny(self):
        self.assert_review(run("client.example.test"))

    def test_fictional_explicit_host_without_grant_matches_missing(self):
        p = policy(explicit_hosts=frozenset({"client.example.test"}))
        self.assert_review(run("client.example.test", p=p))
        self.assertEqual(p.decide(Target("client.example.test")).reason,
                         ScopeReason.AUTHORIZATION_MISSING)

    def test_forged_public_loopback_decision_denied(self):
        fake = ScopeDecision(True, "client.example.test", ScopeReason.LOOPBACK)
        self.assert_hold(run("client.example.test", decision=fake), "decision_policy_mismatch")

    def test_forged_false_public_claim_wrong_reason_denied(self):
        fake = ScopeDecision(False, "client.example.test", ScopeReason.AUTHORIZATION_MISSING)
        self.assert_hold(run("client.example.test", decision=fake), "decision_policy_mismatch")

    def test_forged_allow_truthy_string_denied(self):
        fake = ScopeDecision("yes", "localhost", ScopeReason.LOOPBACK)
        self.assert_hold(run(decision=fake), "decision_type_confusion")

    def test_forged_bool_integer_denied(self):
        fake = ScopeDecision(1, "localhost", ScopeReason.LOOPBACK)
        self.assert_hold(run(decision=fake), "decision_type_confusion")

    def test_forged_reason_string_denied(self):
        fake = ScopeDecision(True, "localhost", "loopback")
        self.assert_hold(run(decision=fake), "decision_type_confusion")

    def test_forged_normalized_host_denied(self):
        fake = ScopeDecision(True, "other.example.test", ScopeReason.LOOPBACK)
        self.assert_hold(run(decision=fake), "decision_target_mismatch")

    def test_forged_host_subclass_denied(self):
        class Alias(str):
            pass
        fake = ScopeDecision(True, Alias("localhost"), ScopeReason.LOOPBACK)
        self.assert_hold(run(decision=fake), "decision_target_mismatch")

    def test_duplicate_dot_fictional_host_denied(self):
        self.assert_hold(run("client..example.test", decision=ScopeDecision(
            False, "client..example.test", ScopeReason.OUT_OF_SCOPE
        )), "nonfictional_target")

    def test_url_with_userinfo_not_considered_fictional_host(self):
        self.assert_hold(run("https://evil@example.test", decision=ScopeDecision(
            False, "example.test", ScopeReason.OUT_OF_SCOPE
        )), "nonfictional_target")

    def test_ipv6_and_private_lab_ineligible_for_reference(self):
        for host in ("::1", "10.0.0.2", "192.0.2.20", "8.8.8.8"):
            with self.subTest(host=host):
                self.assert_hold(run(host, decision=ScopeDecision(
                    False, host, ScopeReason.OUT_OF_SCOPE
                )), "nonfictional_target")

    def test_real_auth_metadata_denied_without_evaluation(self):
        with patch.object(ScopePolicy, "decide", side_effect=AssertionError("do not call")):
            self.assert_hold(run(t=Target("localhost",
                 authorization=Authorization("fiction", "fiction")), decision=ScopeDecision(
                     True, "localhost", ScopeReason.LOOPBACK
                 )), "target_authority_not_allowed")

    def test_nonempty_labels_denied(self):
        t = Target("localhost", labels=("customer",))
        self.assert_hold(run(t=t, decision=ScopeDecision(
            True, "localhost", ScopeReason.LOOPBACK
        )), "target_authority_not_allowed")

    def test_labels_wrong_type_cannot_trigger_untrusted_eq(self):
        class Poison(list):
            def __eq__(self, other):
                raise AssertionError("do not call equality")
        t = Target("localhost", labels=Poison())
        self.assert_hold(run(t=t, decision=ScopeDecision(
            True, "localhost", ScopeReason.LOOPBACK
        )), "target_authority_not_allowed")

    def test_default_private_lab_policy_denied(self):
        self.assert_hold(run(p=ScopePolicy(), decision=ScopeDecision(
            True, "localhost", ScopeReason.LOOPBACK
        )), "non_synthetic_lab_policy")

    def test_public_auth_disabled_denied(self):
        p = policy(require_authorization_for_public=False)
        self.assert_hold(run(p=p, decision=ScopeDecision(
            True, "localhost", ScopeReason.LOOPBACK
        )), "non_synthetic_lab_policy")

    def test_real_explicit_network_denied(self):
        p = policy(explicit_networks=("127.0.0.0/8",))
        self.assert_hold(run(p=p, decision=ScopeDecision(
            True, "localhost", ScopeReason.LOOPBACK
        )), "non_synthetic_lab_policy")

    def test_nonfictional_explicit_host_denied(self):
        p = policy(explicit_hosts=frozenset({"real.example.com"}))
        self.assert_hold(run(p=p, decision=ScopeDecision(
            True, "localhost", ScopeReason.LOOPBACK
        )), "non_synthetic_lab_policy")

    def test_plan_only_activation_is_not_lab_reference(self):
        self.assert_hold(run(a=ActivationPolicy(), decision=ScopeDecision(
            True, "localhost", ScopeReason.LOOPBACK
        )), "invalid_lab_activation")

    def test_authorized_activation_is_not_lab_reference(self):
        self.assert_hold(run(a=ActivationPolicy(ActivationMode.AUTHORIZED, "fiction"),
                             decision=ScopeDecision(True, "localhost", ScopeReason.LOOPBACK)),
                         "invalid_lab_activation")

    def test_non_enum_activation_mode_denied(self):
        self.assert_hold(run(a=ActivationPolicy("lab_only", "fiction"),
                             decision=ScopeDecision(True, "localhost", ScopeReason.LOOPBACK)),
                         "invalid_lab_activation")

    def test_lab_requires_bounded_reference(self):
        for value in (None, "", "secret with spaces", "a" * 65):
            with self.subTest(value=repr(value)[:20]):
                self.assert_hold(run(a=lab(value), decision=ScopeDecision(
                    True, "localhost", ScopeReason.LOOPBACK
                )), "invalid_lab_activation")

    def test_modified_activation_policy_envelope_denied(self):
        a = lab()
        object.__setattr__(a, "injected", "owner")
        self.assert_hold(run(a=a, decision=ScopeDecision(
            True, "localhost", ScopeReason.LOOPBACK
        )), "activation_field_integrity")

    def test_missing_activation_policy_envelope_field_denied(self):
        a = lab()
        object.__delattr__(a, "activation_reference")
        self.assert_hold(run(a=a, decision=ScopeDecision(
            True, "localhost", ScopeReason.LOOPBACK
        )), "activation_field_integrity")

    def test_noncanonical_policy_class_denied(self):
        class Child(ScopePolicy):
            pass
        p = Child(allow_private_lab=False)
        self.assert_hold(run(p=p, decision=ScopeDecision(
            True, "localhost", ScopeReason.LOOPBACK
        )), "invalid_scope_policy")

    def test_no_policy_decide_invocation(self):
        with patch.object(ScopePolicy, "decide",
                          side_effect=AssertionError("never call source")):
            self.assert_review(run(decision=ScopeDecision(
                True, "localhost", ScopeReason.LOOPBACK
            )))

    def test_no_network_process_or_sqlite(self):
        import sqlite3
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("SQLite")):
            self.assert_review(run(decision=ScopeDecision(
                True, "localhost", ScopeReason.LOOPBACK
            )))

    def test_review_result_cannot_be_mutated_to_grant(self):
        r = run("localhost")
        self.assert_review(r)
        with self.assertRaises((AttributeError, TypeError)):
            object.__setattr__(r, "authorizes_execution", True)
        self.assertFalse(r.authorizes_execution)


if __name__ == "__main__":
    unittest.main()
