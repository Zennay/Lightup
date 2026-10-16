"""#1482: strictly local, atomic and non-authorizing decision cohort contract."""
import os
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation_decision_cohort_review_1482 import review_decision_cohort
from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


def real_row(host):
    p = ScopePolicy()
    t = Target(host)
    return (p, t, p.decide(t))


class CohortShapeReviewTests(unittest.TestCase):
    def test_multiple_real_loopback_decisions_are_review_only(self):
        r = review_decision_cohort((real_row("localhost"), real_row("127.0.0.1")))
        self.assertEqual((r.status, r.reason, r.inspected),
                         ("REVIEW_ONLY", "coherent_shape_only", 2))
        self.assertFalse(r.authorizes_execution)
        self.assertFalse(r.authorizes_release)

    def test_real_denied_public_domain_is_not_promoted(self):
        r = review_decision_cohort((real_row("public.example.test"),))
        self.assertEqual(r.status, "REVIEW_ONLY")
        self.assertFalse(r.authorizes_execution)

    def test_invalid_generator_refused_before_iteration(self):
        def hazardous():
            raise AssertionError("generator must never be iterated")
            yield None
        r = review_decision_cohort(hazardous())
        self.assertEqual(r.reason, "invalid_batch")
        self.assertEqual(r.inspected, 0)

    def test_tuple_subclass_refused(self):
        class Batch(tuple):
            pass
        self.assertEqual(
            review_decision_cohort(Batch((real_row("localhost"),))).reason,
            "invalid_batch",
        )

    def test_empty_and_overlimit_refused(self):
        self.assertEqual(review_decision_cohort(()).reason, "invalid_batch")
        self.assertEqual(
            review_decision_cohort((real_row("localhost"),) * 65).reason,
            "invalid_batch",
        )

    def test_list_row_refused(self):
        self.assertEqual(
            review_decision_cohort((list(real_row("localhost")),)).reason,
            "invalid_row",
        )

    def test_tuple_subclass_row_refused(self):
        class Row(tuple):
            pass
        self.assertEqual(
            review_decision_cohort((Row(real_row("localhost")),)).reason,
            "invalid_row",
        )

    def test_malformed_length_refused(self):
        self.assertEqual(
            review_decision_cohort(((ScopePolicy(), Target("localhost")),)).reason,
            "invalid_row",
        )

    def test_invalid_decision_object_refused(self):
        self.assertEqual(
            review_decision_cohort(((ScopePolicy(), Target("localhost"), object()),)).reason,
            "noncanonical_row",
        )

    def test_forged_public_loopback_flag_fail_closed_atomically(self):
        p = ScopePolicy()
        t = Target("public.example.test")
        fake = ScopeDecision(True, "public.example.test", ScopeReason.LOOPBACK)
        r = review_decision_cohort((real_row("localhost"), (p, t, fake)))
        self.assertEqual((r.status, r.reason, r.inspected), ("HOLD", "row_on_hold", 0))
        self.assertFalse(r.authorizes_execution)

    def test_duplicate_target_rejected_even_if_different_notation(self):
        r = review_decision_cohort(
            (real_row("localhost"), real_row("http://localhost/other"))
        )
        self.assertEqual((r.status, r.reason, r.inspected),
                         ("HOLD", "duplicate_host", 0))

    def test_conflicted_allow_boolean_is_hold(self):
        p = ScopePolicy()
        t = Target("localhost")
        wrong = ScopeDecision("yes", "localhost", ScopeReason.LOOPBACK)
        self.assertEqual(
            review_decision_cohort(((p, t, wrong),)).reason,
            "row_on_hold",
        )

    def test_never_calls_policy_decide(self):
        # Precompute source decision before installing the sentinel.
        row = real_row("localhost")
        with patch.object(
            ScopePolicy, "decide", side_effect=AssertionError("no policy call")
        ):
            r = review_decision_cohort((row,))
        self.assertEqual(r.status, "REVIEW_ONLY")

    def test_unexpected_helper_exception_is_hold_not_crash(self):
        with patch(
            "lightup.activation_decision_cohort_review_1482.review_decision_shape",
            side_effect=RuntimeError("synthetic secret identifier"),
        ):
            r = review_decision_cohort((real_row("localhost"),))
        self.assertEqual((r.status, r.reason), ("HOLD", "row_review_error"))
        self.assertNotIn("secret", repr(r))

    def test_no_network_or_subprocess(self):
        import subprocess
        row = real_row("localhost")
        with patch.object(socket, "socket", side_effect=AssertionError("sockets")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            r = review_decision_cohort((row,))
        self.assertEqual(r.status, "REVIEW_ONLY")

    def test_non_authorizing_verdict_is_immutable(self):
        r = review_decision_cohort((real_row("localhost"),))
        with self.assertRaises((AttributeError, TypeError)):
            object.__setattr__(r, "authorizes_execution", True)
        self.assertFalse(r.authorizes_execution)

    def test_min_and_max_accepted_batch_size(self):
        self.assertEqual(review_decision_cohort((real_row("localhost"),)).inspected, 1)
        # 64 unique fictional IPv4 loopbacks without network access.
        rows = tuple(real_row("127.0.0." + str(i)) for i in range(1, 65))
        r = review_decision_cohort(rows)
        self.assertEqual((r.status, r.inspected), ("REVIEW_ONLY", 64))


if __name__ == "__main__":
    unittest.main()
