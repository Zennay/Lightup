"""#886: corrupt legacy evidence decoder must fail with stable ValueError.

Acceptance canaries intentionally xfail until read-source owner #828/#856
integrates strict JSON decoding. No production code or persistence mutations
on rejection (only test fixture corruption inside temporary SQLite).
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import Severity


class CorruptFindingEvidenceDecoderAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = DomainStore(Path(tmp.name) / "corrupt-evidence.sqlite")
        self.operator = AccessContext("operator-qa-886", Role.OPERATOR)
        client = self.store.create_client(self.operator, "QA 886 synthetic client")
        self.engagement = self.store.create_engagement(
            self.operator, client.client_id, "QA 886 synthetic engagement"
        )
        self.finding = self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            title="Synthetic evidence finding",
            severity=Severity.LOW,
            asset="lab://synthetic",
            impact="Synthetic",
            remediation="Synthetic fix",
            evidence_ids=("evidence:synthetic",),
        )

    def _raw(self) -> str:
        with self.store._connect() as con:
            return con.execute(
                "SELECT evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()["evidence_ids_json"]

    def _overwrite(self, raw: str) -> None:
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (raw, self.finding.finding_id),
            )

    def _read(self):
        return self.store.list_findings(
            self.operator, engagement_id=self.engagement.engagement_id
        )

    def _expected_read_failure(self, corrupt: str) -> None:
        self._overwrite(corrupt)
        before = self._raw()
        try:
            self._read()
        except Exception as exc:
            self.assertIs(type(exc), ValueError)  # not JSONDecodeError/TypeError
            self.assertIn("evidence", str(exc).lower())
            # Do not echo raw bytes or accidentally persist repair/normalization.
            self.assertNotIn(corrupt, str(exc))
        else:
            self.fail("corrupt evidence escaped as a readable finding")
        finally:
            self.assertEqual(self._raw(), before)

    @unittest.expectedFailure
    def test_truncated_json_fails_with_canonical_evidence_error(self) -> None:
        self._expected_read_failure('["evidence:synthetic"')

    @unittest.expectedFailure
    def test_invalid_json_object_text_fails_with_canonical_evidence_error(self) -> None:
        self._expected_read_failure('{"partial":')

    @unittest.expectedFailure
    def test_json_null_fails_with_canonical_evidence_error(self) -> None:
        self._expected_read_failure("null")

    @unittest.expectedFailure
    def test_json_number_fails_with_canonical_evidence_error(self) -> None:
        self._expected_read_failure("1234")

    @unittest.expectedFailure
    def test_json_boolean_fails_with_canonical_evidence_error(self) -> None:
        self._expected_read_failure("false")

    def test_canonical_array_stays_readable_and_unchanged(self) -> None:
        before = self._raw()
        self.assertEqual(
            self._read()[0].evidence_ids, ("evidence:synthetic",)
        )
        self.assertEqual(self._raw(), before)

    def test_empty_manual_array_stays_readable_and_unchanged(self) -> None:
        self._overwrite("[]")
        before = self._raw()
        self.assertEqual(self._read()[0].evidence_ids, ())
        self.assertEqual(self._raw(), before)

    def test_fixture_corruption_is_synthetic_and_scoped(self) -> None:
        before = self._raw()
        self.assertEqual(json.loads(before), ["evidence:synthetic"])
        with self.store._connect() as con:
            count = con.execute("SELECT count(*) FROM findings").fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
