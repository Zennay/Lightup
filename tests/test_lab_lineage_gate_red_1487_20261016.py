"""Installed original LAB gate versus untrusted synthetic lineage (#1487).

These source witnesses issue inert in-memory loopback dataclasses only. The
helper is never installed into production, nor is actual scope verified.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.lab_session_lineage_1487 import (
    FictionalLabLineageClaim,
    review_fictional_lab_lineage,
)
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy

NOW = datetime(2030, 1, 1, 12, tzinfo=timezone.utc)


def fictional_lineage(**updates):
    data = dict(
        lab_reference="LAB-SYNTH-001",
        operator_id="ACTOR-SYNTH-001",
        session_id="SESSION-SYNTH-001",
        engagement_id="ENG-SYNTH-001",
        asset_id="ASSET-LOOPBACK-001",
        capability_id="CAP-REVIEW-ONLY",
        starts_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(minutes=10),
        revoked=False,
    )
    data.update(updates)
    return FictionalLabLineageClaim(**data)


class OriginalLabGateUntrustedLineage1487(unittest.TestCase):
    def setUp(self):
        for namespace, symbol in (
            (socket, "socket"),
            (socket, "getaddrinfo"),
            (subprocess, "Popen"),
            (os, "system"),
        ):
            guard = patch.object(
                namespace, symbol, side_effect=AssertionError("no external operations")
            )
            guard.start()
            self.addCleanup(guard.stop)

    @staticmethod
    def _gate(reference, mode=ActivationMode.LAB_ONLY):
        return ActivationGate(
            ScopePolicy(allow_private_lab=False),
            ActivationPolicy(mode=mode, activation_reference=reference),
        )

    @staticmethod
    def _inert_permit(gate):
        return gate.issue(Target("127.0.0.1"), "fictional-review-only")

    def test_canonical_string_reference_still_generates_inert_lab_permit(self):
        permit = self._inert_permit(self._gate("LAB-SYNTH-001"))
        self.assertEqual(permit.activation_reference, "LAB-SYNTH-001")
        self.assertEqual(permit.mode, ActivationMode.LAB_ONLY)

    def test_claim_review_only_is_not_any_authorization(self):
        receipt = review_fictional_lab_lineage((fictional_lineage(),), NOW)
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self.assertIs(receipt.grants_authority, False)
        self.assertIs(receipt.can_dispatch, False)
        self.assertIs(receipt.can_issue_permit, False)

    def test_real_source_witness_valid_lineage_object_is_retained_as_reference(self):
        claim = fictional_lineage()
        permit = self._inert_permit(self._gate(claim))
        self.assertIs(permit.activation_reference, claim)
        self.assertIs(permit.mode, ActivationMode.LAB_ONLY)

    def test_real_source_witness_revoked_claim_retained_as_reference(self):
        claim = fictional_lineage(revoked=True)
        self.assertEqual(review_fictional_lab_lineage((claim,), NOW).status, "HOLD")
        permit = self._inert_permit(self._gate(claim))
        self.assertIs(permit.activation_reference, claim)

    def test_real_source_witness_expired_claim_retained_as_reference(self):
        claim = fictional_lineage(expires_at=NOW - timedelta(minutes=1))
        self.assertEqual(review_fictional_lab_lineage((claim,), NOW).status, "HOLD")
        permit = self._inert_permit(self._gate(claim))
        self.assertIs(permit.activation_reference, claim)

    def test_real_source_witness_malformed_asset_claim_retained_as_reference(self):
        claim = fictional_lineage(asset_id="ASSET-OTHER-999")
        self.assertEqual(review_fictional_lab_lineage((claim,), NOW).status, "REVIEW_ONLY")
        permit = self._inert_permit(self._gate(claim))
        self.assertIs(permit.activation_reference, claim)
        self.assertNotEqual(claim.asset_id, "ASSET-LOOPBACK-001")

    def test_plan_only_never_issues_from_lineage(self):
        with self.assertRaises(PermissionError):
            self._inert_permit(self._gate(fictional_lineage(), ActivationMode.PLAN_ONLY))

    def test_lab_only_cannot_expand_to_fictional_public_host(self):
        claim = fictional_lineage()
        gate = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset({"public.example.test"})),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference=claim),
        )
        with self.assertRaises(PermissionError):
            gate.issue(
                Target(
                    "public.example.test",
                    authorization=Authorization(
                        owner="fictional", reference="CONSENT-FICTIONAL"
                    ),
                ),
                "fictional-review-only",
            )

    @unittest.expectedFailure
    def test_source_red_reject_untrusted_lineage_object_at_gate_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            self._gate(fictional_lineage())

    @unittest.expectedFailure
    def test_source_red_reject_revoked_lineage_object_at_gate_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            self._gate(fictional_lineage(revoked=True))

    @unittest.expectedFailure
    def test_source_red_reject_expired_lineage_object_at_gate_construction(self):
        with self.assertRaises((ValueError, TypeError)):
            self._gate(fictional_lineage(expires_at=NOW - timedelta(minutes=1)))

    @unittest.expectedFailure
    def test_source_red_reject_asset_mismatched_lineage_reference_before_permit(self):
        claim = fictional_lineage(asset_id="ASSET-OTHER-999")
        with self.assertRaises((PermissionError, TypeError, ValueError)):
            self._inert_permit(self._gate(claim))


if __name__ == "__main__":
    unittest.main()
