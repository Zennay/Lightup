"""Offline reference for exactly-once consumption of remediation retest receipts.

This module is deliberately NOT a production authorization implementation.
"""
from dataclasses import dataclass
import re
import unittest


_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


@dataclass(frozen=True)
class Receipt:
    tenant: str
    finding: str
    revision: int
    proof_digest: str
    decision_id: str


def valid(receipt):
    return (
        type(receipt) is Receipt
        and all(type(v) is str and _ID.fullmatch(v) for v in
                (receipt.tenant, receipt.finding, receipt.decision_id))
        and type(receipt.revision) is int and receipt.revision > 0
        and type(receipt.proof_digest) is str
        and _DIGEST.fullmatch(receipt.proof_digest) is not None
    )


class ConsumptionLedger:
    """Pure memory reference: a trusted, atomic store must replace this."""

    def __init__(self):
        self._used_decisions = set()
        self._used_proofs = set()

    def consume(self, receipt, expected_tenant, expected_finding, expected_revision):
        if not valid(receipt):
            return False
        if (type(expected_tenant) is not str or
                type(expected_finding) is not str or
                type(expected_revision) is not int):
            return False
        if (receipt.tenant, receipt.finding, receipt.revision) != (
                expected_tenant, expected_finding, expected_revision):
            return False
        decision_key = (receipt.tenant, receipt.decision_id)
        proof_key = (receipt.tenant, receipt.proof_digest)
        if decision_key in self._used_decisions or proof_key in self._used_proofs:
            return False
        self._used_decisions.add(decision_key)
        self._used_proofs.add(proof_key)
        return True


class RetestConsumptionOnceTests(unittest.TestCase):
    def setUp(self):
        self.ledger = ConsumptionLedger()
        self.receipt = Receipt("tenant-a", "finding-a", 3, "a" * 64, "decision-a")

    def consume(self, r=None, tenant="tenant-a", finding="finding-a", revision=3):
        return self.ledger.consume(r if r is not None else self.receipt,
                                   tenant, finding, revision)

    def test_initial_exact_context_accepted_conditionally(self):
        self.assertTrue(self.consume())

    def test_second_identical_receipt_rejected(self):
        self.assertTrue(self.consume())
        self.assertFalse(self.consume())

    def test_same_decision_new_digest_rejected(self):
        self.assertTrue(self.consume())
        self.assertFalse(self.consume(Receipt("tenant-a", "finding-a", 3,
                                              "b" * 64, "decision-a")))

    def test_same_digest_new_decision_rejected(self):
        self.assertTrue(self.consume())
        self.assertFalse(self.consume(Receipt("tenant-a", "finding-b", 3,
                                              "a" * 64, "decision-b"),
                                      finding="finding-b"))

    def test_cross_tenant_isolation_of_reference_keys(self):
        self.assertTrue(self.consume())
        self.assertTrue(self.consume(Receipt("tenant-b", "finding-a", 3,
                                             "a" * 64, "decision-a"),
                                     tenant="tenant-b"))

    def test_context_mismatch_does_not_consume(self):
        self.assertFalse(self.consume(finding="finding-b"))
        self.assertTrue(self.consume())

    def test_stale_revision_does_not_consume(self):
        self.assertFalse(self.consume(revision=4))
        self.assertTrue(self.consume())

    def test_boolean_revision_rejected(self):
        self.assertFalse(self.consume(Receipt("tenant-a", "finding-a", True,
                                              "a" * 64, "decision-a")))

    def test_noncanonical_digest_rejected(self):
        self.assertFalse(self.consume(Receipt("tenant-a", "finding-a", 3,
                                              "A" * 64, "decision-a")))

    def test_ambiguous_identifier_rejected(self):
        self.assertFalse(self.consume(Receipt("tenant-a ", "finding-a", 3,
                                              "a" * 64, "decision-a"),
                                      tenant="tenant-a "))

    def test_wrong_type_rejected(self):
        self.assertFalse(self.consume({"tenant": "tenant-a"}))

    def test_failed_attempt_does_not_poison_ledger(self):
        self.assertFalse(self.consume(Receipt("tenant-a", "finding-a", 3,
                                              "invalid", "decision-a")))
        self.assertTrue(self.consume())

    def test_receipt_immutable(self):
        from dataclasses import FrozenInstanceError
        with self.assertRaises(FrozenInstanceError):
            self.receipt.tenant = "tenant-b"

    def test_subclass_rejected(self):
        class FakeReceipt(Receipt):
            pass
        self.assertFalse(self.consume(FakeReceipt("tenant-a", "finding-a", 3,
                                                  "a" * 64, "decision-a")))


if __name__ == "__main__":
    unittest.main()
