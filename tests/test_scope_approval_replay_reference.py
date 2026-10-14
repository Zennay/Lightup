"""Offline candidate-model checks; never a production authorization or dispatch test."""
import json
import unittest
from dataclasses import dataclass
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "scope_approval_replay_matrix.json"


@dataclass(frozen=True)
class Approval:
    approval_id: str
    request_id: str
    tenant: str
    revision: int


class InMemorySingleUseReference:
    """Proposed atomic-consume semantics, deliberately only in-memory."""

    def __init__(self, approvals):
        self._approvals = dict(approvals)
        self._consumed = set()

    def evaluate(self, approval_id, request_id, tenant, revision):
        approval = self._approvals.get(approval_id)
        if approval is None:
            return "deny_missing_approval"
        if approval.request_id != request_id:
            return "deny_request_mismatch"
        if approval.tenant != tenant:
            return "deny_tenant_mismatch"
        if approval.revision != revision:
            return "deny_revision_mismatch"
        if approval_id in self._consumed:
            return "deny_replay"
        self._consumed.add(approval_id)
        return "conditionally_eligible"


class ApprovalReplayReferenceTests(unittest.TestCase):
    def setUp(self):
        self.cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
        self.ledger = InMemorySingleUseReference({
            "ap-a": Approval("ap-a", "req-a", "tenant-a", 1),
            "ap-c": Approval("ap-c", "req-c", "tenant-a", 1),
        })

    def test_declarative_matrix_matches_reference_model(self):
        for case in self.cases:
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    self.ledger.evaluate(case["approval_id"], case["request_id"], case["tenant"], case["revision"]),
                    case["expect"],
                )

    def test_denied_mismatch_does_not_consume_valid_approval(self):
        self.assertEqual(self.ledger.evaluate("ap-a", "req-incorrect", "tenant-a", 1), "deny_request_mismatch")
        self.assertEqual(self.ledger.evaluate("ap-a", "req-a", "tenant-a", 1), "conditionally_eligible")
        self.assertEqual(self.ledger.evaluate("ap-a", "req-a", "tenant-a", 1), "deny_replay")

    def test_missing_approval_denied_without_consuming_other_approval(self):
        self.assertEqual(self.ledger.evaluate("not-issued", "req-a", "tenant-a", 1), "deny_missing_approval")
        self.assertEqual(self.ledger.evaluate("ap-c", "req-c", "tenant-a", 1), "conditionally_eligible")

    def test_separate_reference_instances_do_not_prove_durable_replay_prevention(self):
        """Explicitly demonstrate why a durable, issuer-owned atomic ledger is required."""
        self.assertEqual(self.ledger.evaluate("ap-a", "req-a", "tenant-a", 1), "conditionally_eligible")
        restarted = InMemorySingleUseReference({"ap-a": Approval("ap-a", "req-a", "tenant-a", 1)})
        self.assertEqual(restarted.evaluate("ap-a", "req-a", "tenant-a", 1), "conditionally_eligible")


if __name__ == "__main__":
    unittest.main()
