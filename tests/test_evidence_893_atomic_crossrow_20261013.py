"""Real disposable SQLite retest atomicity acceptance for issue #893.

Intentional expected failures characterize the unchanged legacy producer.
There is no executed remediation, real retest, scan, target or authorization.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import RetestStatus, Severity


class DurableRetestCrossRowAtomicityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-retest-lab-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "domain.sqlite3"
        self.store = DomainStore(self.path)
        self.operator = AccessContext("operator-atomicity-lab", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Synthetic review only")
        engagement = self.store.create_engagement(
            self.operator, client.client_id, "Synthetic retest state"
        )
        self.first = self.store.record_finding(
            self.operator, engagement.engagement_id,
            title="First synthetic finding", severity=Severity.LOW,
            asset="lab://synthetic-first", impact="Synthetic impact",
            remediation="No execution", evidence_ids=("evidence:first",),
        )
        self.second = self.store.record_finding(
            self.operator, engagement.engagement_id,
            title="Second synthetic finding", severity=Severity.LOW,
            asset="lab://synthetic-second", impact="Synthetic impact",
            remediation="No execution", evidence_ids=("evidence:second",),
        )

    def _snapshot(self):
        with self.store._connect() as con:
            return tuple(
                tuple(row) for row in con.execute(
                    "SELECT finding_id, retest_status, evidence_ids_json "
                    "FROM findings ORDER BY finding_id"
                ).fetchall()
            )

    def _replace_evidence(self, finding_id: str, raw: str):
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (raw, finding_id),
            )

    def _assert_rejected_without_write(self, raw: str, to_status: RetestStatus):
        self._replace_evidence(self.second.finding_id, raw)
        before = self._snapshot()
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.store.set_retest_status(
                self.operator, self.second.finding_id, to_status
            )
        self.assertEqual(self._snapshot(), before, "failed decode mutated SQLite")
        # Reopen the file; the invariant must be durable, not only cached in memory.
        reopened = DomainStore(self.path)
        with reopened._connect() as con:
            after_reopen = tuple(
                tuple(row) for row in con.execute(
                    "SELECT finding_id,retest_status,evidence_ids_json "
                    "FROM findings ORDER BY finding_id"
                ).fetchall()
            )
        self.assertEqual(after_reopen, before)

    def test_canonical_independent_retest_transitions_survive_sqlite_reopen(self):
        self.store.set_retest_status(
            self.operator, self.first.finding_id, RetestStatus.FIX_PENDING
        )
        self.store.set_retest_status(
            self.operator, self.second.finding_id, RetestStatus.FIXED
        )
        reopened = DomainStore(self.path)
        with reopened._connect() as con:
            rows = {
                row["finding_id"]: row["retest_status"]
                for row in con.execute("SELECT finding_id,retest_status FROM findings")
            }
        self.assertEqual(rows[self.first.finding_id], RetestStatus.FIX_PENDING.value)
        self.assertEqual(rows[self.second.finding_id], RetestStatus.FIXED.value)

    def test_unknown_finding_does_not_mutate_other_durable_rows(self):
        before = self._snapshot()
        with self.assertRaises(KeyError):
            self.store.set_retest_status(
                self.operator, "unknown-synthetic-id", RetestStatus.FIXED
            )
        self.assertEqual(self._snapshot(), before)

    @unittest.expectedFailure
    def test_invalid_json_rolls_back_after_other_finding_was_fixed(self):
        self.store.set_retest_status(
            self.operator, self.first.finding_id, RetestStatus.FIXED
        )
        self._assert_rejected_without_write(
            '["evidence:second"', RetestStatus.REGRESSION
        )

    @unittest.expectedFailure
    def test_json_object_cannot_be_reinterpreted_as_evidence_tuple(self):
        self.store.set_retest_status(
            self.operator, self.second.finding_id, RetestStatus.FIX_PENDING
        )
        self._assert_rejected_without_write(
            '{"evidence:second":"synthetic"}', RetestStatus.FIXED
        )

    @unittest.expectedFailure
    def test_duplicate_persisted_evidence_cannot_mark_a_retest_fixed(self):
        self._assert_rejected_without_write(
            '["evidence:second","evidence:second"]', RetestStatus.FIXED
        )

    @unittest.expectedFailure
    def test_null_persisted_evidence_cannot_mark_regression(self):
        self._assert_rejected_without_write(
            "null", RetestStatus.REGRESSION
        )


if __name__ == "__main__":
    unittest.main()
