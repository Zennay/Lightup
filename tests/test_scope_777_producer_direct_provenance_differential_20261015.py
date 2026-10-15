"""Issue #777: producer-to-direct-policy approval-provenance differential.

Synthetic SQLite and in-memory decisions only. This intentionally does NOT
grant permissions, contact an asset, or change installed source.
"""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


class SyntheticString(str):
    """A type-confused value which ordinary annotations do not prohibit."""


class ApprovalProvenanceDifferentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-777-offline-")
        self.addCleanup(self.temp.cleanup)
        self.store = DomainStore(Path(self.temp.name) / "synthetic.sqlite")
        self.operator = AccessContext("fictional-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Fictional Lab Customer")
        self.engagement = self.store.create_engagement(
            self.operator, client.client_id, "Fictional Authorization Review"
        )
        now = datetime.now(timezone.utc)
        self.start = now - timedelta(days=1)
        self.end = now + timedelta(days=1)
        self.scope = ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("fictional-check",),
        )
        self.policy = ExecutionPolicy()

    def _issue(self, approved_by="fictional-operator", reference="ROE-FICTIONAL"):
        return self.store.record_authorization_grant(
            self.operator, self.engagement.engagement_id, approved_by,
            reference, self.scope, self.start, self.end
        )

    def _decide(self, grant):
        return self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="example.test",
            capability_id="fictional-check",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=grant,
        ))

    def _assert_direct_rejected_without_durable_mutation(self, **replacement):
        canonical = self._issue()
        before = self.store.list_authorization_grants(
            self.operator, self.engagement.engagement_id
        )
        modified = replace(canonical, **replacement)
        snapshot = dict(modified.__dict__)
        result = self._decide(modified)
        self.assertFalse(result.allowed, "direct noncanonical provenance must not authorize")
        self.assertEqual(modified.__dict__, snapshot)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator, self.engagement.engagement_id
            ),
            before,
            "policy decision must not change durable grant state",
        )

    def test_issued_provenance_canonicalized_and_roundtrips(self):
        issued = self._issue("  fictional-operator  ", " ROE-FICTIONAL ")
        self.assertEqual((issued.approved_by, issued.reference),
                         ("fictional-operator", "ROE-FICTIONAL"))
        persisted = self.store.list_authorization_grants(
            self.operator, self.engagement.engagement_id
        )
        self.assertEqual(len(persisted), 1)
        self.assertEqual((persisted[0].approved_by, persisted[0].reference),
                         ("fictional-operator", "ROE-FICTIONAL"))
        self.assertTrue(self._decide(persisted[0]).allowed)

    def test_producer_rejects_blank_without_persisted_effect(self):
        candidates = [
            ("", "ROE-FICTIONAL"), ("   ", "ROE-FICTIONAL"),
            ("fictional-operator", ""), ("fictional-operator", " \t "),
        ]
        for actor, reference in candidates:
            with self.subTest(actor=repr(actor), reference=repr(reference)):
                with self.assertRaises(ValueError):
                    self._issue(actor, reference)
                self.assertEqual(
                    self.store.list_authorization_grants(
                        self.operator, self.engagement.engagement_id
                    ), []
                )

    def test_canonical_direct_value_remains_allowed_without_writes(self):
        grant = self._issue()
        original = self.store.list_authorization_grants(
            self.operator, self.engagement.engagement_id
        )
        self.assertTrue(self._decide(grant).allowed)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator, self.engagement.engagement_id
            ), original
        )

    # These are RED acceptance controls against the current, unintegrated
    # direct ExecutionPolicy. A green test suite with these xfails is NOT
    # evidence that production rejects malformed in-memory grant objects.
    @unittest.expectedFailure
    def test_red_empty_approver(self):
        self._assert_direct_rejected_without_durable_mutation(approved_by="")

    @unittest.expectedFailure
    def test_red_whitespace_approver(self):
        self._assert_direct_rejected_without_durable_mutation(approved_by=" \t ")

    @unittest.expectedFailure
    def test_red_padded_approver(self):
        self._assert_direct_rejected_without_durable_mutation(
            approved_by=" fictional-operator "
        )

    @unittest.expectedFailure
    def test_red_polymorphic_approver(self):
        self._assert_direct_rejected_without_durable_mutation(
            approved_by=SyntheticString("fictional-operator")
        )

    @unittest.expectedFailure
    def test_red_empty_reference(self):
        self._assert_direct_rejected_without_durable_mutation(reference="")

    @unittest.expectedFailure
    def test_red_whitespace_reference(self):
        self._assert_direct_rejected_without_durable_mutation(reference="\t ")

    @unittest.expectedFailure
    def test_red_padded_reference(self):
        self._assert_direct_rejected_without_durable_mutation(
            reference=" ROE-FICTIONAL "
        )

    @unittest.expectedFailure
    def test_red_polymorphic_reference(self):
        self._assert_direct_rejected_without_durable_mutation(
            reference=SyntheticString("ROE-FICTIONAL")
        )


if __name__ == "__main__":
    unittest.main()
