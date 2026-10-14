"""Offline trust-root reference for evidence receipts; no production wiring or I/O."""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class RegisteredEvidence:
    evidence_id: str
    tenant_id: str
    run_id: str
    finding_id: str
    digest: str
    issuer: str
    revoked: bool = False


class TrustedEvidenceLedger:
    """Stand-in for server-owned, independently authenticated receipt provenance."""

    def __init__(self, records):
        self._records = dict(records)

    def admit(self, candidate, *, tenant, run, finding, digest, issuer):
        if type(candidate) is not str or not candidate:
            return False
        actual = self._records.get(candidate)
        if type(actual) is not RegisteredEvidence or type(actual.revoked) is not bool:
            return False
        if actual.revoked:
            return False
        selectors = (tenant, run, finding, digest, issuer)
        if any(type(value) is not str or not value for value in selectors):
            return False
        return selectors == (actual.tenant_id, actual.run_id, actual.finding_id,
                             actual.digest, actual.issuer)


class TrustedLedgerReferenceTests(unittest.TestCase):
    def setUp(self):
        self.record = RegisteredEvidence("ev-1", "tenant-A", "run-A",
                                         "finding-A", "hash-A", "issuer-A")
        self.ledger = TrustedEvidenceLedger({self.record.evidence_id: self.record})
        self.kw = dict(tenant="tenant-A", run="run-A", finding="finding-A",
                       digest="hash-A", issuer="issuer-A")

    def test_valid_registered_record_conditional_match(self):
        self.assertTrue(self.ledger.admit("ev-1", **self.kw))

    def test_unknown_evidence_id_rejected(self):
        self.assertFalse(self.ledger.admit("ev-missing", **self.kw))

    def test_untrusted_caller_cannot_rebind_ledger_record(self):
        self.assertFalse(self.ledger.admit("ev-1", **{**self.kw, "tenant": "tenant-B"}))
        self.assertTrue(self.ledger.admit("ev-1", **self.kw))

    def test_each_binding_and_issuer_checked_against_trusted_record(self):
        for key in self.kw:
            with self.subTest(key=key):
                self.assertFalse(self.ledger.admit("ev-1", **{**self.kw, key: "other"}))

    def test_revoked_or_truthy_substitute_cannot_match(self):
        for marker in (True, 1, "yes"):
            with self.subTest(marker=marker):
                entry = RegisteredEvidence("ev-1", "tenant-A", "run-A",
                                            "finding-A", "hash-A", "issuer-A", marker)
                ledger = TrustedEvidenceLedger({"ev-1": entry})
                self.assertFalse(ledger.admit("ev-1", **self.kw))

    def test_subclass_record_cannot_substitute_trusted_registration(self):
        class Impostor(RegisteredEvidence):
            pass
        ledger = TrustedEvidenceLedger({"ev-1": Impostor(**vars(self.record))})
        self.assertFalse(ledger.admit("ev-1", **self.kw))

    def test_invalid_selectors_rejected(self):
        for marker in (None, True, 1, b"issuer-A", ""):
            with self.subTest(marker=marker):
                self.assertFalse(self.ledger.admit("ev-1", **{**self.kw, "issuer": marker}))

    def test_read_is_pure(self):
        original = vars(self.record).copy()
        self.assertFalse(self.ledger.admit("ev-1", **{**self.kw, "run": "wrong"}))
        self.assertEqual(vars(self.record), original)


if __name__ == "__main__":
    unittest.main()
