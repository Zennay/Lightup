from __future__ import annotations

import dataclasses
import json
import unittest
from unittest.mock import patch

import test_future_subject_resolution as fixtures
from lightup.domain import AccessContext, Role, TenantIsolationError
from lightup.future_subject_resolution import apply_future_subject_resolution
from lightup.future_subject_review import review_future_subjects


class FutureSubjectReviewTest(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.FutureSubjectResolutionTest(
            "test_verified_subject_resolution_preserves_candidate_and_attack_paths"
        )
        self.f.setUp()
        self.addCleanup(self.f.tearDown)
        self.client = AccessContext("client-user", Role.CLIENT_MEMBER, "client-1")
        self.operator = AccessContext("operator", Role.OPERATOR)

    def test_single_candidate_is_pending_and_never_a_security_pass(self):
        report = review_future_subjects(self.f.bound, self.f.state, self.client)
        self.assertEqual(report.unresolved_change_count, 1)
        self.assertFalse(report.subject_review_complete)
        item = report.items[0]
        self.assertEqual(item.candidate_subject_ids, ("api-1",))
        self.assertEqual(item.review_status, "pending")
        self.assertEqual(item.next_action, "record_explicit_subject_review")
        self.assertIsNone(item.verified_subject_id)
        self.assertEqual(item.evidence_refs, ())
        self.assertEqual(report.future_semantics, "unresolved")
        self.assertEqual(report.security_verdict, "not_evaluated")

    def test_verified_review_is_read_only_and_exports_detached_json(self):
        resolved = apply_future_subject_resolution(
            self.f.bound, self.f.resolution, self.f.state
        )
        before = dataclasses.asdict(resolved)
        report = review_future_subjects(resolved, self.f.state, self.client)
        self.assertTrue(report.subject_review_complete)
        self.assertEqual(report.unresolved_change_count, 0)
        item = report.items[0]
        self.assertEqual(item.verified_subject_id, "api-1")
        self.assertEqual(item.decision_id, "decision-1")
        self.assertEqual(item.review_basis, "operator_reviewed")
        self.assertEqual(item.evidence_refs, (f"evidence:{self.f.evidence_id}",))
        self.assertEqual(item.next_action, "await_effect_graph_resolution")
        self.assertEqual(report.security_verdict, "not_evaluated")
        exported = json.loads(json.dumps(report.as_dict()))
        exported["items"][0]["verified_subject_id"] = "mutated"
        self.assertEqual(item.verified_subject_id, "api-1")
        self.assertEqual(dataclasses.asdict(resolved), before)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            item.review_status = "pending"

    def test_cross_tenant_rejection_happens_before_evidence_lookup(self):
        other = AccessContext("other-user", Role.CLIENT_ADMIN, "client-2")
        with patch.object(self.f.state, "get_evidence") as lookup:
            with self.assertRaises(TenantIsolationError):
                review_future_subjects(self.f.bound, self.f.state, other)
            with self.assertRaises(TenantIsolationError):
                review_future_subjects(
                    self.f.bound, self.f.state, other, client_id="client-1"
                )
            lookup.assert_not_called()

    def test_operator_must_select_the_exact_client(self):
        with self.assertRaises(ValueError):
            review_future_subjects(self.f.bound, self.f.state, self.operator)
        with self.assertRaises(TenantIsolationError):
            review_future_subjects(
                self.f.bound, self.f.state, self.operator, client_id="client-2"
            )
        report = review_future_subjects(
            self.f.bound, self.f.state, self.operator, client_id="client-1"
        )
        self.assertEqual(report.client_id, "client-1")

    def test_deleted_verified_evidence_cannot_appear_as_approved(self):
        resolved = apply_future_subject_resolution(
            self.f.bound, self.f.resolution, self.f.state
        )
        with self.f.state.connect() as connection:
            connection.execute(
                "DELETE FROM evidence WHERE evidence_id=?", (self.f.evidence_id,)
            )
        with self.assertRaisesRegex(KeyError, "unknown evidence"):
            review_future_subjects(resolved, self.f.state, self.client)

    def test_partial_verified_state_is_rejected_instead_of_partially_reported(self):
        resolved = apply_future_subject_resolution(
            self.f.bound, self.f.resolution, self.f.state
        )
        corrupt = dataclasses.replace(
            resolved, facts=tuple(
                fact for fact in resolved.facts
                if fact.predicate != "future_subject.basis"
            )
        )
        with self.assertRaises(ValueError):
            review_future_subjects(corrupt, self.f.state, self.client)

    def test_report_remains_readable_after_unrelated_snapshot_advance(self):
        resolved = apply_future_subject_resolution(
            self.f.bound, self.f.resolution, self.f.state
        )
        later = resolved.next_snapshot()
        report = review_future_subjects(later, self.f.state, self.client)
        self.assertTrue(report.subject_review_complete)
        self.assertEqual(report.twin_version, later.version)
        # Reading an existing decision does not replay a snapshot-bound write.
        self.assertEqual(report.items[0].decision_id, "decision-1")

    def test_forged_binding_summary_cannot_be_rendered_as_complete(self):
        metadata = dict(self.f.bound.metadata)
        metadata["future_subject_binding_count"] = "0"
        corrupt = dataclasses.replace(
            self.f.bound, metadata=tuple(sorted(metadata.items()))
        )
        with self.assertRaises(ValueError):
            review_future_subjects(corrupt, self.f.state, self.client)


if __name__ == "__main__":
    unittest.main()
