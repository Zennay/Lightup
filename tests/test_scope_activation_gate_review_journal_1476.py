"""Observational monotone HOLD journal tests against real installed gate (#1476)."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.scope import ScopePolicy
from lightup.activation_gate_lifetime_review_1476 import LifetimeStatus
from lightup.activation_gate_review_journal_1476 import (
    OfflineCohortJournal,
    advance_offline_cohort_journal,
    begin_offline_cohort_journal,
)


def gate():
    return ActivationGate(ScopePolicy(), ActivationPolicy())


class CohortJournalTests(unittest.TestCase):
    def assert_never_authorizes(self, receipt):
        for attr in (
            "may_issue_permit", "may_issue_grant", "may_dispatch",
            "may_scan", "may_deploy", "may_release",
        ):
            self.assertIs(getattr(receipt, attr), False)

    def test_stable_gate_is_review_only_not_authority(self):
        g = gate()
        journal = begin_offline_cohort_journal((g,))
        self.assertIsNotNone(journal)
        step = advance_offline_cohort_journal((g,), journal)
        self.assertIs(step.receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assertEqual(step.next_journal.observation_count, 1)
        self.assertIs(step.next_journal.held, False)
        self.assert_never_authorizes(step.receipt)

    def test_stable_multiple_rounds_are_pure(self):
        g1, g2 = gate(), gate()
        journal = begin_offline_cohort_journal((g1, g2))
        for i in range(1, 5):
            step = advance_offline_cohort_journal((g1, g2), journal)
            self.assertIs(step.receipt.status, LifetimeStatus.REVIEW_ONLY)
            self.assertEqual(step.next_journal.observation_count, i)
            self.assert_never_authorizes(step.receipt)
            journal = step.next_journal

    def test_invalid_first_cohort_refuses_journal(self):
        g = gate()
        self.assertIsNone(begin_offline_cohort_journal(()))
        self.assertIsNone(begin_offline_cohort_journal((g, g)))
        self.assertIsNone(begin_offline_cohort_journal([g]))

    def test_single_observed_change_latches_hold(self):
        g = gate()
        journal = begin_offline_cohort_journal((g,))
        g.activation_policy = ActivationPolicy(ActivationMode.LAB_ONLY, "FAKE")
        step = advance_offline_cohort_journal((g,), journal)
        self.assertIs(step.receipt.status, LifetimeStatus.HOLD)
        self.assertIs(step.next_journal.held, True)
        self.assert_never_authorizes(step.receipt)

    def test_hold_survives_restoring_original_policy_object(self):
        g = gate()
        original = g.activation_policy
        journal = begin_offline_cohort_journal((g,))
        g.activation_policy = ActivationPolicy(ActivationMode.LAB_ONLY)
        held = advance_offline_cohort_journal((g,), journal)
        self.assertIs(held.receipt.status, LifetimeStatus.HOLD)
        g.activation_policy = original
        # A direct fresh snapshot comparison would now be REVIEW_ONLY,
        # but the *continued same journal chain* remembers the observed HOLD.
        again = advance_offline_cohort_journal((g,), held.next_journal)
        self.assertIs(again.receipt.status, LifetimeStatus.HOLD)
        self.assertIs(again.next_journal.held, True)
        self.assert_never_authorizes(again.receipt)

    def test_hold_is_sticky_across_different_gate_batches(self):
        a, b = gate(), gate()
        journal = begin_offline_cohort_journal((a, b))
        b.scope_policy = ScopePolicy(explicit_hosts=frozenset({"offline.example.test"}))
        step = advance_offline_cohort_journal((a, b), journal)
        self.assertIs(step.receipt.status, LifetimeStatus.HOLD)
        later = advance_offline_cohort_journal((a,), step.next_journal)
        self.assertIs(later.receipt.status, LifetimeStatus.HOLD)
        self.assert_never_authorizes(later.receipt)

    def test_invalid_journal_types_are_hold_without_exception(self):
        g = gate()
        for bad in (None, object(), "", 0):
            with self.subTest(kind=type(bad).__name__):
                step = advance_offline_cohort_journal((g,), bad)
                self.assertIsNone(step.next_journal)
                self.assertIs(step.receipt.status, LifetimeStatus.HOLD)
                self.assert_never_authorizes(step.receipt)

    def test_noncanonical_held_and_counter_types_are_denied(self):
        g = gate()
        original = begin_offline_cohort_journal((g,))
        for held, count in ((1, 0), ("False", 0), (False, True), (False, -1), (False, 1025)):
            with self.subTest(held=held, count=count):
                fake = OfflineCohortJournal(
                    cohort=original.cohort, held=held, observation_count=count
                )
                step = advance_offline_cohort_journal((g,), fake)
                self.assertIs(step.receipt.status, LifetimeStatus.HOLD)
                self.assertIsNone(step.next_journal)
                self.assert_never_authorizes(step.receipt)

    def test_exact_1024th_observation_limit(self):
        g = gate()
        original = begin_offline_cohort_journal((g,))
        prior = OfflineCohortJournal(original.cohort, held=False, observation_count=1023)
        done = advance_offline_cohort_journal((g,), prior)
        self.assertIs(done.receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assertEqual(done.next_journal.observation_count, 1024)
        rejected = advance_offline_cohort_journal((g,), done.next_journal)
        self.assertIs(rejected.receipt.status, LifetimeStatus.HOLD)
        self.assertIs(rejected.next_journal.held, True)
        self.assert_never_authorizes(rejected.receipt)

    def test_bogus_cohort_is_rejected(self):
        g = gate()
        fake = OfflineCohortJournal(cohort=object())
        step = advance_offline_cohort_journal((g,), fake)
        self.assertIs(step.receipt.status, LifetimeStatus.HOLD)
        self.assertIsNone(step.next_journal)

    def test_incomplete_journal_is_generic_hold(self):
        g = gate()
        fake = object.__new__(OfflineCohortJournal)
        step = advance_offline_cohort_journal((g,), fake)
        self.assertIs(step.receipt.status, LifetimeStatus.HOLD)
        self.assertIsNone(step.next_journal)

    def test_journal_repr_does_not_expose_policy_references(self):
        fake_ref = "SYNTHETIC-SENSITIVE-" + "Q" * 45
        g = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset({"offline.example.test"})),
            ActivationPolicy(ActivationMode.AUTHORIZED, fake_ref),
        )
        journal = begin_offline_cohort_journal((g,))
        step = advance_offline_cohort_journal((g,), journal)
        for value in (repr(journal), repr(step), repr(step.receipt)):
            self.assertNotIn(fake_ref, value)
            self.assertNotIn("offline.example.test", value)
        self.assert_never_authorizes(step.receipt)

    def test_offline_journal_never_issues_permit_or_network(self):
        g = gate()
        with patch.object(ActivationGate, "issue", side_effect=AssertionError("permit forbidden")), \
             patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns forbidden")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            journal = begin_offline_cohort_journal((g,))
            step = advance_offline_cohort_journal((g,), journal)
        self.assertIs(step.receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assert_never_authorizes(step.receipt)

    def test_old_journal_is_not_a_trustworthy_replay_protection(self):
        g = gate()
        first = begin_offline_cohort_journal((g,))
        original = g.activation_policy
        g.activation_policy = ActivationPolicy(ActivationMode.LAB_ONLY)
        held = advance_offline_cohort_journal((g,), first)
        self.assertIs(held.receipt.status, LifetimeStatus.HOLD)
        g.activation_policy = original
        # Deliberately prove the limitation: reusing an *old* journal
        # bypasses the optional history. The observer is never authority.
        stale = advance_offline_cohort_journal((g,), first)
        self.assertIs(stale.receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assert_never_authorizes(stale.receipt)


if __name__ == "__main__":
    unittest.main()
