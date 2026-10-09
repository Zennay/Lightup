"""Offline reference: negative authorization evidence is monotonic within an evaluation.

This is a proposed invariant, NOT a production authorization gate.
No sockets, DNS, scanners, target requests or production imports.
"""
from __future__ import annotations

from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Evaluation:
    tenant: str
    request_id: str
    revision: int
    authority: frozenset[str]
    denial_evidence: frozenset[str]


def evaluate(snapshot: Evaluation, requested: str, evidence: frozenset[str]) -> bool:
    """A standalone fail-closed reference, not a LightUp execution decision."""
    if type(snapshot) is not Evaluation:
        return False
    if not all(type(x) is str and x for x in (snapshot.tenant, snapshot.request_id, requested)):
        return False
    if type(snapshot.revision) is not int or snapshot.revision < 1:
        return False
    if type(snapshot.authority) is not frozenset or type(snapshot.denial_evidence) is not frozenset:
        return False
    if type(evidence) is not frozenset:
        return False
    if any(type(x) is not str or not x for x in snapshot.authority | snapshot.denial_evidence | evidence):
        return False
    if snapshot.denial_evidence | evidence:
        return False
    return requested in snapshot.authority


class NegativeEvidenceMonotonicReferenceTests(unittest.TestCase):
    def setUp(self):
        self.snap = Evaluation("tenant-a", "request-1", 1, frozenset({"header-check"}), frozenset())

    def test_canonical_positive_is_only_reference_eligible(self):
        self.assertTrue(evaluate(self.snap, "header-check", frozenset()))

    def test_absent_capability_stays_denied(self):
        self.assertFalse(evaluate(self.snap, "service-scan", frozenset()))

    def test_any_new_denial_evidence_cannot_restore_allow(self):
        for evidence in ("revoked", "expired", "scope_mismatch", "approval_missing", "lease_conflict"):
            with self.subTest(evidence=evidence):
                self.assertFalse(evaluate(self.snap, "header-check", frozenset({evidence})))

    def test_accumulation_cannot_override_existing_deny(self):
        first = frozenset({"revoked"})
        second = first | {"reviewed", "new_allow"}
        self.assertFalse(evaluate(self.snap, "header-check", first))
        self.assertFalse(evaluate(self.snap, "header-check", second))

    def test_snapshot_denial_cannot_be_cleared_by_callsite(self):
        denied = Evaluation("tenant-a", "request-1", 1, self.snap.authority, frozenset({"expired"}))
        self.assertFalse(evaluate(denied, "header-check", frozenset()))

    def test_noncanonical_negative_evidence_fails_closed(self):
        for value in ([], {"revoked"}, None, "revoked", frozenset({123})):
            with self.subTest(value=value):
                self.assertFalse(evaluate(self.snap, "header-check", value))

    def test_noncanonical_revision_fails_closed(self):
        for value in (0, -1, True, 1.0, "1"):
            with self.subTest(value=value):
                snap = Evaluation("tenant-a", "request-1", value, self.snap.authority, frozenset())
                self.assertFalse(evaluate(snap, "header-check", frozenset()))

    def test_evaluation_is_immutable(self):
        original = self.snap
        self.assertFalse(evaluate(original, "header-check", frozenset({"revoked"})))
        self.assertEqual(original, self.snap)
        self.assertTrue(evaluate(original, "header-check", frozenset()))


if __name__ == "__main__":
    unittest.main()
