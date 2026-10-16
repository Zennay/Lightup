"""Real installed-source, synthetic cohort review regressions (#1476).

All test actors/hostnames are fictional. No grant, handler, scan or network.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
import lightup.activation_gate_cohort_review_1476 as cohort
from lightup.scope import ScopePolicy
from lightup.activation_gate_cohort_review_1476 import (
    PinnedGateCohort,
    pin_gate_cohort_for_offline_review,
    review_gate_cohort_offline,
)
from lightup.activation_gate_lifetime_review_1476 import (
    LifetimeStatus,
    PinnedGateReview,
)


def gate() -> ActivationGate:
    return ActivationGate(ScopePolicy(), ActivationPolicy())


class CohortReviewTests(unittest.TestCase):
    def assert_denies_everything(self, receipt):
        for name in (
            "may_issue_permit", "may_issue_grant", "may_dispatch",
            "may_scan", "may_deploy", "may_release",
        ):
            self.assertIs(getattr(receipt, name), False)

    def test_single_unchanged_gate_is_review_only_not_approval(self):
        g = gate()
        pin = pin_gate_cohort_for_offline_review((g,))
        receipt = review_gate_cohort_offline((g,), pin)
        self.assertIs(receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assertEqual(receipt.reason, "unchanged")
        self.assert_denies_everything(receipt)

    def test_multiple_independent_gates_review_atomically(self):
        gates = (
            gate(),
            ActivationGate(ScopePolicy(), ActivationPolicy(ActivationMode.LAB_ONLY, "FICTIONAL")),
            ActivationGate(
                ScopePolicy(explicit_hosts=frozenset({"offline.example.test"})),
                ActivationPolicy(ActivationMode.AUTHORIZED, "FAKE-REVIEW"),
            ),
        )
        pin = pin_gate_cohort_for_offline_review(gates)
        self.assertIs(type(pin), PinnedGateCohort)
        receipt = review_gate_cohort_offline(gates, pin)
        self.assertIs(receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assert_denies_everything(receipt)

    def test_empty_cohort_denied(self):
        self.assertIsNone(pin_gate_cohort_for_offline_review(()))
        self.assertIs(review_gate_cohort_offline((), object()).status, LifetimeStatus.HOLD)

    def test_list_and_generator_cohorts_are_rejected(self):
        a = gate()
        for obj in ([a], (x for x in (a,)), {a: "fake"}):
            self.assertIsNone(pin_gate_cohort_for_offline_review(obj))
            self.assertIs(review_gate_cohort_offline(obj, object()).status, LifetimeStatus.HOLD)

    def test_exact_64_gate_bound_inclusive(self):
        gates = tuple(gate() for _ in range(64))
        pin = pin_gate_cohort_for_offline_review(gates)
        self.assertIsNotNone(pin)
        self.assertIs(review_gate_cohort_offline(gates, pin).status, LifetimeStatus.REVIEW_ONLY)

    def test_reject_65_gates_without_partial_review(self):
        gates = tuple(gate() for _ in range(65))
        self.assertIsNone(pin_gate_cohort_for_offline_review(gates))
        self.assertIs(review_gate_cohort_offline(gates, object()).status, LifetimeStatus.HOLD)

    def test_duplicate_gate_identity_denied_at_pin(self):
        a = gate()
        self.assertIsNone(pin_gate_cohort_for_offline_review((a, a)))

    def test_duplicate_gate_identity_denied_at_review(self):
        a, b = gate(), gate()
        pin = pin_gate_cohort_for_offline_review((a, b))
        receipt = review_gate_cohort_offline((a, a), pin)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.assert_denies_everything(receipt)

    def test_one_bad_gate_denies_all(self):
        a, b, c = gate(), gate(), gate()
        pin = pin_gate_cohort_for_offline_review((a, b, c))
        b.activation_policy = ActivationPolicy(ActivationMode.LAB_ONLY)
        receipt = review_gate_cohort_offline((a, b, c), pin)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.assertEqual(receipt.reason, "changed")
        self.assert_denies_everything(receipt)

    def test_one_bad_scope_denies_all(self):
        gates = tuple(gate() for _ in range(5))
        pin = pin_gate_cohort_for_offline_review(gates)
        gates[-1].scope_policy = ScopePolicy(
            explicit_hosts=frozenset({"fictional.example.test"})
        )
        self.assertIs(review_gate_cohort_offline(gates, pin).status, LifetimeStatus.HOLD)

    def test_reordered_gates_are_not_silently_matched(self):
        a, b = gate(), gate()
        pin = pin_gate_cohort_for_offline_review((a, b))
        self.assertIs(review_gate_cohort_offline((b, a), pin).status, LifetimeStatus.HOLD)

    def test_changed_cohort_size_is_hold(self):
        a, b = gate(), gate()
        pin = pin_gate_cohort_for_offline_review((a, b))
        self.assertIs(review_gate_cohort_offline((a,), pin).status, LifetimeStatus.HOLD)
        self.assertIs(review_gate_cohort_offline((a, b, gate()), pin).status, LifetimeStatus.HOLD)

    def test_replaced_equal_policy_is_also_hold(self):
        a, b = gate(), gate()
        pin = pin_gate_cohort_for_offline_review((a, b))
        a.activation_policy = ActivationPolicy()
        self.assertIs(review_gate_cohort_offline((a, b), pin).status, LifetimeStatus.HOLD)

    def test_invalid_policy_in_one_gate_denies_entire_pin(self):
        a, b = gate(), gate()
        b.activation_policy = ActivationPolicy(ActivationMode.AUTHORIZED)
        self.assertIsNone(pin_gate_cohort_for_offline_review((a, b)))

    def test_subclass_gate_in_cohort_denied(self):
        class FakeGate(ActivationGate):
            pass
        self.assertIsNone(pin_gate_cohort_for_offline_review(
            (gate(), FakeGate(ScopePolicy(), ActivationPolicy()))
        ))

    def test_corrupt_nested_dataclass_denies_batch(self):
        a, b = gate(), gate()
        pin = pin_gate_cohort_for_offline_review((a, b))
        object.__delattr__(b.scope_policy, "explicit_hosts")
        receipt = review_gate_cohort_offline((a, b), pin)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.assert_denies_everything(receipt)

    def test_forged_bad_pin_entry_is_generic_hold(self):
        a = gate()
        forged = PinnedGateCohort(pins=(object(),))
        receipt = review_gate_cohort_offline((a,), forged)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.assert_denies_everything(receipt)

    def test_incomplete_pin_instance_is_generic_hold(self):
        a = gate()
        malformed = object.__new__(PinnedGateCohort)
        receipt = review_gate_cohort_offline((a,), malformed)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.assert_denies_everything(receipt)

    def test_uninitialized_gate_is_generic_hold(self):
        a = object.__new__(ActivationGate)
        self.assertIsNone(pin_gate_cohort_for_offline_review((a,)))
        pin = pin_gate_cohort_for_offline_review((gate(),))
        self.assertIs(review_gate_cohort_offline((a,), pin).status, LifetimeStatus.HOLD)

    def test_non_tuple_pin_entries_refuse_without_leak(self):
        a = gate()
        bad = PinnedGateCohort(pins=[object()])
        self.assertIs(review_gate_cohort_offline((a,), bad).status, LifetimeStatus.HOLD)

    def test_cohort_does_not_call_permit_or_external_effects(self):
        a, b = gate(), gate()
        with patch.object(ActivationGate, "issue", side_effect=AssertionError("permit forbidden")), \
             patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns forbidden")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            pin = pin_gate_cohort_for_offline_review((a, b))
            receipt = review_gate_cohort_offline((a, b), pin)
        self.assertIs(receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assert_denies_everything(receipt)

    def test_pin_rechecks_earlier_gate_when_later_gate_changes_it(self):
        a, b = gate(), gate()
        original = cohort.pin_gate_for_offline_review

        def pin_with_mutation(g):
            result = original(g)
            if g is b:
                a.activation_policy = ActivationPolicy(ActivationMode.LAB_ONLY)
            return result

        with patch.object(cohort, "pin_gate_for_offline_review", side_effect=pin_with_mutation):
            self.assertIsNone(pin_gate_cohort_for_offline_review((a, b)))

    def test_review_rechecks_earlier_gate_after_later_gate_mutation(self):
        a, b = gate(), gate()
        pinned = pin_gate_cohort_for_offline_review((a, b))
        original = cohort.review_gate_lifetime
        calls = []

        def review_with_mutation(g, pin):
            result = original(g, pin)
            calls.append(g)
            if g is b and len(calls) == 2:
                a.scope_policy = ScopePolicy(
                    explicit_hosts=frozenset({"fictional.example.test"})
                )
            return result

        with patch.object(cohort, "review_gate_lifetime", side_effect=review_with_mutation):
            receipt = review_gate_cohort_offline((a, b), pinned)
        self.assertIs(receipt.status, LifetimeStatus.HOLD)
        self.assertEqual(receipt.reason, "changed")
        self.assertIn(a, calls[2:])
        self.assert_denies_everything(receipt)

    def test_stable_cohort_gets_second_complete_review_pass(self):
        a, b, c = gate(), gate(), gate()
        pinned = pin_gate_cohort_for_offline_review((a, b, c))
        original = cohort.review_gate_lifetime
        with patch.object(cohort, "review_gate_lifetime", wraps=original) as spy:
            receipt = review_gate_cohort_offline((a, b, c), pinned)
        self.assertIs(receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assertEqual(spy.call_count, 6)
        self.assert_denies_everything(receipt)

    def test_receipt_and_pin_repr_do_not_echo_metadata(self):
        secret = "SYNTHETIC-PRIVATE-" + "Z" * 60
        a = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset({"test.example.test"})),
            ActivationPolicy(ActivationMode.AUTHORIZED, secret),
        )
        pin = pin_gate_cohort_for_offline_review((a,))
        receipt = review_gate_cohort_offline((a,), pin)
        self.assertNotIn(secret, repr(pin))
        self.assertNotIn(secret, repr(receipt))
        self.assertNotIn("test.example.test", repr(pin))
        self.assert_denies_everything(receipt)


if __name__ == "__main__":
    unittest.main()
