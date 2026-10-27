"""Expected-RED exact status-type / durable atomicity proof for open #893.

These exercises are synthetic disposable SQLite only. Original DomainStore,
source owners, assessment authorization and deployed retest paths are untouched.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role, RoleError
from lightup.models import RetestStatus, Severity


class ForgedStatus:
    def __init__(self, value):
        self.value = value


class ExactRetestStatusAtomicityRedTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-retest-status-type-")
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "retest.sqlite3"
        self.store = DomainStore(self.path)
        self.operator = AccessContext("operator-type-lab", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Synthetic status type client")
        engagement = self.store.create_engagement(
            self.operator, client.client_id, "Synthetic status type engagement"
        )
        self.client_member = AccessContext("client-type-lab", Role.CLIENT_MEMBER, client.client_id)
        self.finding = self.store.record_finding(
            self.operator, engagement.engagement_id,
            title="Status type fixture", severity=Severity.LOW,
            asset="lab://not-an-external-target", impact="Synthetic",
            remediation="No executable repair",
            evidence_ids=("evidence:fixture",),
        )

    def _row(self):
        with self.store._connect() as conn:
            row = conn.execute(
                "SELECT retest_status,evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        return tuple(row)

    def _assert_denial_before_write(self, fake_status):
        before = self._row()
        with self.assertRaisesRegex(ValueError, "retest.*status|status.*type"):
            self.store.set_retest_status(
                self.operator, self.finding.finding_id, fake_status
            )
        self.assertEqual(self._row(), before)
        reopened = DomainStore(self.path)
        with reopened._connect() as conn:
            after = conn.execute(
                "SELECT retest_status,evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        self.assertEqual(tuple(after), before)

    def test_operator_canonical_enum_transition_is_still_durable(self):
        result = self.store.set_retest_status(
            self.operator, self.finding.finding_id, RetestStatus.FIX_PENDING
        )
        self.assertIs(result.retest_status, RetestStatus.FIX_PENDING)
        self.assertEqual(self._row(), (RetestStatus.FIX_PENDING.value, '["evidence:fixture"]'))

    def test_client_cannot_mutate_retest_status(self):
        before = self._row()
        with self.assertRaises(RoleError):
            self.store.set_retest_status(
                self.client_member, self.finding.finding_id, RetestStatus.FIX_PENDING
            )
        self.assertEqual(self._row(), before)

    def test_unknown_id_does_not_mutate_valid_record(self):
        before = self._row()
        with self.assertRaises(KeyError):
            self.store.set_retest_status(
                self.operator, "absent-fixture", RetestStatus.FIX_PENDING
            )
        self.assertEqual(self._row(), before)

    @unittest.expectedFailure
    def test_object_spoofing_canonical_value_must_not_be_an_enum(self):
        self._assert_denial_before_write(ForgedStatus(RetestStatus.FIX_PENDING.value))

    @unittest.expectedFailure
    def test_unknown_status_value_must_be_denied_without_durable_corruption(self):
        self._assert_denial_before_write(ForgedStatus("verified_without_proof"))

    @unittest.expectedFailure
    def test_boolean_status_value_must_be_denied_before_db_mutation(self):
        self._assert_denial_before_write(ForgedStatus(True))

    @unittest.expectedFailure
    def test_plain_text_status_must_use_controlled_error_not_attribute_error(self):
        self._assert_denial_before_write("fixed")


if __name__ == "__main__":
    unittest.main()
