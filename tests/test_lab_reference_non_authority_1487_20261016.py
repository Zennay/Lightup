"""Proof that an offline LAB review receipt is NOT a permit/consent (#1487).

All permits in this module are inert in-memory dataclasses for fictional loopback.
Known source acceptance gaps are separately marked as expected failures.
"""
from dataclasses import FrozenInstanceError
import os
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.lab_reference_review_1487 import (
    LabReferenceReview,
    review_lab_reference_batch,
    review_lab_reference_history,
)
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


class LabReviewerCannotAuthorize1487(unittest.TestCase):
    def setUp(self):
        for method, name in (
            (socket, "socket"),
            (socket, "getaddrinfo"),
            (subprocess, "Popen"),
            (os, "system"),
        ):
            guard = patch.object(method, name, side_effect=AssertionError("no external effects"))
            guard.start()
            self.addCleanup(guard.stop)

    @staticmethod
    def _gate(reference):
        return ActivationGate(
            ScopePolicy(allow_private_lab=False),
            ActivationPolicy(
                mode=ActivationMode.LAB_ONLY,
                activation_reference=reference,
            ),
        )

    @staticmethod
    def _permit(gate):
        return gate.issue(Target("127.0.0.1"), "fictional-review-only")

    def test_two_gates_without_references_repeat_unattributed_lab_label(self):
        first = self._permit(self._gate(None))
        second = self._permit(self._gate(None))
        self.assertEqual((first.activation_reference, second.activation_reference), ("LAB", "LAB"))
        self.assertTrue(first.permit_id)
        self.assertTrue(second.permit_id)
        self.assertNotEqual(first.permit_id, second.permit_id)

    def test_two_distinct_inert_lab_permits_can_share_caller_claimed_reference(self):
        first = self._permit(self._gate("LAB-SYNTHETIC-001"))
        second = self._permit(self._gate("LAB-SYNTHETIC-001"))
        self.assertEqual(first.activation_reference, second.activation_reference)
        self.assertNotEqual(first.permit_id, second.permit_id)

    def test_review_only_receipt_is_rejected_as_decision_authority_by_reviewer(self):
        receipt = review_lab_reference_history((), ("LAB-SESSION-001",))
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self.assertIs(receipt.grants_authority, False)
        self.assertIs(receipt.can_issue_permit, False)
        self.assertIs(receipt.can_dispatch, False)
        self.assertIs(receipt.can_release, False)
        self.assertIs(type(receipt), LabReferenceReview)

    def test_source_witness_review_only_receipt_currently_passes_reference_annotation(self):
        receipt = review_lab_reference_batch(("LAB-SESSION-001",))
        permit = self._permit(self._gate(receipt))
        self.assertIs(permit.activation_reference, receipt)
        self.assertIs(permit.mode, ActivationMode.LAB_ONLY)
        self.assertIs(receipt.can_issue_permit, False)

    def test_source_witness_hold_receipt_currently_passes_reference_annotation(self):
        receipt = review_lab_reference_history(
            ("LAB-SESSION-001",), ("LAB-SESSION-001",)
        )
        self.assertEqual(receipt.status, "HOLD")
        permit = self._permit(self._gate(receipt))
        self.assertIs(permit.activation_reference, receipt)
        self.assertIs(receipt.grants_authority, False)

    @unittest.expectedFailure
    def test_source_red_review_only_object_must_not_be_accepted_as_lab_reference(self):
        receipt = review_lab_reference_batch(("LAB-SESSION-001",))
        with self.assertRaises((TypeError, ValueError)):
            self._gate(receipt)

    @unittest.expectedFailure
    def test_source_red_hold_object_must_not_be_accepted_as_lab_reference(self):
        receipt = review_lab_reference_history(
            ("LAB-SESSION-001",), ("LAB-SESSION-001",)
        )
        with self.assertRaises((TypeError, ValueError)):
            self._gate(receipt)

    def test_plan_only_never_grants_from_review_only_receipt(self):
        receipt = review_lab_reference_batch(("LAB-SESSION-001",))
        gate = ActivationGate(
            ScopePolicy(),
            ActivationPolicy(mode=ActivationMode.PLAN_ONLY, activation_reference=receipt),
        )
        with self.assertRaises(PermissionError):
            self._permit(gate)

    def test_review_only_receipt_does_not_widen_public_lab_scope(self):
        receipt = review_lab_reference_batch(("LAB-SESSION-001",))
        gate = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset({"public.example.test"})),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference=receipt),
        )
        target = Target(
            "public.example.test",
            Authorization(owner="fictional", reference="CONSENT-SYNTHETIC"),
        )
        with self.assertRaises(PermissionError):
            gate.issue(target, "fictional-review-only")

    def test_review_receipt_is_not_modified_by_inert_gate(self):
        receipt = review_lab_reference_batch(("LAB-SESSION-001",))
        self._permit(self._gate(receipt))
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self.assertIs(receipt.can_issue_permit, False)
        with self.assertRaises(FrozenInstanceError):
            receipt.can_issue_permit = True


if __name__ == "__main__":
    unittest.main()
