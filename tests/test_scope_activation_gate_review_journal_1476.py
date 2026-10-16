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
    OfflineReviewSession,
    open_offline_review_session,
    advance_offline_review_session,
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

    def test_session_cursor_stable_two_steps(self):
        g = gate()
        session = open_offline_review_session((g,))
        first = session.current
        one = advance_offline_review_session((g,), session, first)
        self.assertIs(one.receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assertIs(session.current, one.next_journal)
        two = advance_offline_review_session((g,), session, one.next_journal)
        self.assertIs(two.receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assertEqual(session.current.observation_count, 2)
        self.assert_never_authorizes(one.receipt)
        self.assert_never_authorizes(two.receipt)

    def test_session_rejects_stale_success_cursor_permanently(self):
        g = gate()
        session = open_offline_review_session((g,))
        stale = session.current
        one = advance_offline_review_session((g,), session, stale)
        self.assertIs(one.receipt.status, LifetimeStatus.REVIEW_ONLY)
        replay = advance_offline_review_session((g,), session, stale)
        self.assertIs(replay.receipt.status, LifetimeStatus.HOLD)
        self.assert_never_authorizes(replay.receipt)
        again = advance_offline_review_session((g,), session, one.next_journal)
        self.assertIs(again.receipt.status, LifetimeStatus.HOLD)

    def test_session_rejects_equal_value_new_cursor(self):
        g = gate()
        session = open_offline_review_session((g,))
        equivalent = OfflineCohortJournal(
            session.current.cohort, held=False, observation_count=0
        )
        self.assertIsNot(equivalent, session.current)
        step = advance_offline_review_session((g,), session, equivalent)
        self.assertIs(step.receipt.status, LifetimeStatus.HOLD)
        self.assert_never_authorizes(step.receipt)

    def test_session_detects_policy_swap_then_keeps_hold_after_repair(self):
        g = gate()
        original = g.activation_policy
        session = open_offline_review_session((g,))
        g.activation_policy = ActivationPolicy(ActivationMode.LAB_ONLY)
        bad = advance_offline_review_session((g,), session, session.current)
        self.assertIs(bad.receipt.status, LifetimeStatus.HOLD)
        g.activation_policy = original
        later = advance_offline_review_session((g,), session, session.current)
        self.assertIs(later.receipt.status, LifetimeStatus.HOLD)
        self.assert_never_authorizes(later.receipt)

    def test_session_works_for_multiple_gates_and_rejects_one_drift(self):
        a, b = gate(), gate()
        session = open_offline_review_session((a, b))
        good = advance_offline_review_session((a, b), session, session.current)
        self.assertIs(good.receipt.status, LifetimeStatus.REVIEW_ONLY)
        b.scope_policy = ScopePolicy(explicit_hosts=frozenset({"offline.example.test"}))
        fail = advance_offline_review_session((a, b), session, session.current)
        self.assertIs(fail.receipt.status, LifetimeStatus.HOLD)
        self.assert_never_authorizes(fail.receipt)

    def test_session_invalid_cohorts_not_constructed(self):
        g = gate()
        self.assertIsNone(open_offline_review_session(()))
        self.assertIsNone(open_offline_review_session((g, g)))
        self.assertIsNone(open_offline_review_session([g]))
        self.assertIsNone(open_offline_review_session(tuple(gate() for _ in range(65))))

    def test_session_wrong_type_returns_generic_hold(self):
        g = gate()
        for bad in (object(), OfflineCohortJournal, None, 123):
            step = advance_offline_review_session((g,), bad, object())
            self.assertIs(step.receipt.status, LifetimeStatus.HOLD)
            self.assertIsNone(step.next_journal)
            self.assert_never_authorizes(step.receipt)

    def test_session_rejects_missing_or_invalid_private_fields(self):
        g = gate()
        session = open_offline_review_session((g,))
        original = session.current
        session._terminal = "false"
        invalid = advance_offline_review_session((g,), session, original)
        self.assertIs(invalid.receipt.status, LifetimeStatus.HOLD)
        self.assert_never_authorizes(invalid.receipt)
        broken = object.__new__(OfflineReviewSession)
        missing = advance_offline_review_session((g,), broken, original)
        self.assertIs(missing.receipt.status, LifetimeStatus.HOLD)

    def test_session_limit_latches_hold(self):
        g = gate()
        session = open_offline_review_session((g,))
        session._current = OfflineCohortJournal(
            session.current.cohort, held=False, observation_count=1024
        )
        maxed = advance_offline_review_session((g,), session, session.current)
        self.assertIs(maxed.receipt.status, LifetimeStatus.HOLD)
        self.assertIs(session.current.held, True)
        later = advance_offline_review_session((g,), session, session.current)
        self.assertIs(later.receipt.status, LifetimeStatus.HOLD)
        self.assert_never_authorizes(later.receipt)

    def test_session_no_policy_metadata_in_repr(self):
        ref = "FICTIONAL-CONFIDENTIAL-" + "X" * 45
        g = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset({"offline.example.test"})),
            ActivationPolicy(ActivationMode.AUTHORIZED, ref),
        )
        session = open_offline_review_session((g,))
        step = advance_offline_review_session((g,), session, session.current)
        self.assertNotIn(ref, repr(session))
        self.assertNotIn(ref, repr(step))
        self.assertNotIn("offline.example.test", repr(session))
        self.assert_never_authorizes(step.receipt)

    def test_session_never_calls_real_issue_or_io(self):
        g = gate()
        with patch.object(ActivationGate, "issue", side_effect=AssertionError("permit forbidden")), \\
             patch.object(socket, "socket", side_effect=AssertionError("socket forbidden")), \\
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns forbidden")), \\
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            session = open_offline_review_session((g,))
            step = advance_offline_review_session((g,), session, session.current)
        self.assertIs(step.receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assert_never_authorizes(step.receipt)

    def test_new_session_is_not_durable_revocation_guarantee(self):
        g = gate()
        original = g.activation_policy
        session = open_offline_review_session((g,))
        g.activation_policy = ActivationPolicy(ActivationMode.LAB_ONLY)
        held = advance_offline_review_session((g,), session, session.current)
        self.assertIs(held.receipt.status, LifetimeStatus.HOLD)
        g.activation_policy = original
        # This intentional LIMITATION means no new session is a trusted
        # permit, durable revocation marker, or security audit log.
        brand_new = open_offline_review_session((g,))
        new_step = advance_offline_review_session((g,), brand_new, brand_new.current)
        self.assertIs(new_step.receipt.status, LifetimeStatus.REVIEW_ONLY)
        self.assert_never_authorizes(new_step.receipt)

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
