"""Deterministic offline approval-consumption interleavings; not production integration."""
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor


class AtomicCandidateLedger:
    """Thread-local reference semantics sharing a single in-memory lock and consume set."""
    def __init__(self):
        self._lock = threading.Lock()
        self._used = set()

    def consume(self, key, *, valid=True):
        if not valid:
            return False
        with self._lock:
            if key in self._used:
                return False
            self._used.add(key)
            return True


class ApprovalReplayInterleavingContractTests(unittest.TestCase):
    def test_concurrent_same_key_has_exactly_one_candidate_success(self):
        ledger = AtomicCandidateLedger()
        barrier = threading.Barrier(8)

        def attempt(_):
            barrier.wait(timeout=5)
            return ledger.consume(("tenant-a", "req-a", "ap-a", 1))

        with ThreadPoolExecutor(max_workers=8) as executor:
            result = list(executor.map(attempt, range(8)))
        self.assertEqual(sum(result), 1)

    def test_distinct_tenants_can_use_distinct_approvals(self):
        ledger = AtomicCandidateLedger()
        keys = [("tenant-a", "req-a", "ap-a", 1), ("tenant-b", "req-b", "ap-b", 1)]
        self.assertTrue(all(ledger.consume(key) for key in keys))

    def test_denial_does_not_consume_reference_approval(self):
        ledger = AtomicCandidateLedger()
        key = ("tenant-a", "req-a", "ap-a", 1)
        self.assertFalse(ledger.consume(key, valid=False))
        self.assertTrue(ledger.consume(key))
        self.assertFalse(ledger.consume(key))

    def test_revision_change_needs_independent_issuer_decision(self):
        ledger = AtomicCandidateLedger()
        old = ("tenant-a", "req-a", "ap-a", 1)
        new = ("tenant-a", "req-a", "ap-a", 2)
        self.assertTrue(ledger.consume(old))
        # A naive tuple-keyed ledger treats a forged revision as unused.
        # This intentionally demonstrates why the production issuer must validate lineage.
        self.assertTrue(ledger.consume(new))


if __name__ == "__main__":
    unittest.main()
