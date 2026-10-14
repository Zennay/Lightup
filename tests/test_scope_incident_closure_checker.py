"""Offline fail-closed tests for incident closure evidence shape."""
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_scope_incident_closure import closure_is_proven  # noqa: E402


def sample():
    return {
        "incident_id": "INC-1", "observed_at_utc": "2026-10-08T00:00:00Z",
        "tenant_id": "tenant-A", "engagement_id": "eng-1", "run_id": "run-1",
        "grant_id": "grant-1", "expected_version": "v1", "observed_version": "v2",
        "revoked_or_narrowed_dimensions": ["capability"],
        "queued_child_ids": ["queue-1"], "inflight_child_ids": ["child-1"],
        "stop_requested_at": "2026-10-08T00:01:00Z",
        "stop_acknowledged_at": "2026-10-08T00:02:00Z",
        "terminal_state_by_child": {"queue-1": "cancelled", "child-1": "failed"},
        "audit_receipt_refs": ["sha256:illustrative-test-receipt"],
        "reviewer_id": "reviewer", "review_at_utc": "2026-10-08T00:03:00Z",
        "closure_decision": "approved_closed",
    }


class IncidentClosureCheckerTests(unittest.TestCase):
    def test_complete_shape_only_passes(self):
        self.assertTrue(closure_is_proven(sample()))

    def test_missing_field_rejected(self):
        for name in sample():
            with self.subTest(name=name):
                record = sample()
                del record[name]
                self.assertFalse(closure_is_proven(record))

    def test_unknown_extra_field_rejected(self):
        record = sample()
        record["permission"] = "active"
        self.assertFalse(closure_is_proven(record))

    def test_unverified_child_rejected(self):
        for state in ("unknown", "running", "cancel_requested", "success", ""):
            with self.subTest(state=state):
                record = sample()
                record["terminal_state_by_child"]["child-1"] = state
                self.assertFalse(closure_is_proven(record))

    def test_acknowledgement_without_terminal_evidence_rejected(self):
        record = sample()
        del record["terminal_state_by_child"]["child-1"]
        self.assertFalse(closure_is_proven(record))

    def test_cross_tenant_duplicated_or_unexpected_child_rejected(self):
        record = sample()
        record["terminal_state_by_child"]["foreign-child"] = "cancelled"
        self.assertFalse(closure_is_proven(record))

    def test_duplicate_child_across_queues_rejected(self):
        record = sample()
        record["inflight_child_ids"] = ["queue-1"]
        self.assertFalse(closure_is_proven(record))

    def test_unapproved_closure_rejected(self):
        for decision in ("open", "pending", "approved", True, None):
            with self.subTest(decision=decision):
                record = sample()
                record["closure_decision"] = decision
                self.assertFalse(closure_is_proven(record))

    def test_missing_audit_or_incident_reason_rejected(self):
        for field in ("audit_receipt_refs", "revoked_or_narrowed_dimensions"):
            record = sample()
            record[field] = []
            self.assertFalse(closure_is_proven(record))

    def test_noncanonical_container_types_rejected(self):
        record = sample()
        record["queued_child_ids"] = ("queue-1",)
        self.assertFalse(closure_is_proven(record))
        record = sample()
        record["terminal_state_by_child"] = [("queue-1", "cancelled")]
        self.assertFalse(closure_is_proven(record))

    def test_input_is_not_mutated(self):
        record = sample()
        before = copy.deepcopy(record)
        closure_is_proven(record)
        self.assertEqual(record, before)


if __name__ == "__main__":
    unittest.main()
