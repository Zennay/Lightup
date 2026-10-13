"""Supplemental disposable SQLite audit-trigger acceptance for #893.

Tests marked expectedFailure document real default-reader/write gaps. This does
NOT alter DomainStore, execute a retest, authorize an assessment or grant rights.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import RetestStatus, Severity


class RetestAuditAtomicityAcceptance(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="lightup-retest-audit-lab-")
        self.addCleanup(tmp.cleanup)
        self.store = DomainStore(Path(tmp.name) / "domain.sqlite3")
        self.operator = AccessContext("synthetic-audit-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Synthetic client only")
        engagement = self.store.create_engagement(
            self.operator, client.client_id, "Synthetic engagement only"
        )
        self.finding = self.store.record_finding(
            self.operator, engagement.engagement_id,
            title="Synthetic evidence finding", severity=Severity.LOW,
            asset="lab://none", impact="No real impact",
            remediation="No remediation execution",
            evidence_ids=("evidence:test",),
        )
        with self.store._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE retest_audit (
                    finding_id TEXT NOT NULL,
                    old_status TEXT NOT NULL,
                    new_status TEXT NOT NULL
                );
                CREATE TRIGGER synthetic_retest_audit
                AFTER UPDATE OF retest_status ON findings
                BEGIN
                    INSERT INTO retest_audit(finding_id, old_status, new_status)
                    VALUES(OLD.finding_id, OLD.retest_status, NEW.retest_status);
                END;
                """
            )

    def _state(self):
        with self.store._connect() as connection:
            finding = connection.execute(
                "SELECT retest_status, evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
            events = connection.execute(
                "SELECT finding_id, old_status, new_status FROM retest_audit"
            ).fetchall()
        return tuple(finding), tuple(tuple(row) for row in events)

    def _corrupt_evidence(self, raw):
        with self.store._connect() as connection:
            connection.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (raw, self.finding.finding_id),
            )

    def test_valid_synthetic_status_update_emits_exactly_one_audit_event(self):
        before, events = self._state()
        self.assertEqual(events, ())
        updated = self.store.set_retest_status(
            self.operator, self.finding.finding_id, RetestStatus.FIX_PENDING
        )
        after, events = self._state()
        self.assertIs(updated.retest_status, RetestStatus.FIX_PENDING)
        self.assertEqual(after[1], before[1])
        self.assertEqual(
            events, (
                (
                    self.finding.finding_id,
                    RetestStatus.NOT_TESTED.value,
                    RetestStatus.FIX_PENDING.value,
                ),
            )
        )

    def test_unknown_finding_id_produces_no_audit_event(self):
        before = self._state()
        with self.assertRaises(KeyError):
            self.store.set_retest_status(
                self.operator, "missing-synthetic-finding", RetestStatus.FIX_PENDING
            )
        self.assertEqual(self._state(), before)

    @unittest.expectedFailure
    def test_malformed_json_failure_must_not_commit_status_or_audit(self):
        self._corrupt_evidence('["evidence:test"')
        before = self._state()
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.store.set_retest_status(
                self.operator, self.finding.finding_id, RetestStatus.FIX_PENDING
            )
        self.assertEqual(self._state(), before, "failed decode left audit/status writes")

    @unittest.expectedFailure
    def test_valid_json_object_evidence_must_not_commit_status_or_audit(self):
        self._corrupt_evidence('{"evidence:test": "synthetic"}')
        before = self._state()
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.store.set_retest_status(
                self.operator, self.finding.finding_id, RetestStatus.FIX_PENDING
            )
        self.assertEqual(self._state(), before, "shape rejection left audit/status writes")


if __name__ == "__main__":
    unittest.main()
