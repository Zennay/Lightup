"""W36 disposable SQLite acceptance for the optional batch adapter."""
import sqlite3
import unittest
from unittest.mock import patch

from lightup.domain import FindingRecord
from lightup.finding_batch_checked_optin_w33 import checked_findings_batch
import lightup.finding_batch_checked_optin_w33 as batch


class BatchMapperAcceptanceW36(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.execute(
            "CREATE TABLE findings (finding_id TEXT, client_id TEXT, "
            "engagement_id TEXT, title TEXT, severity TEXT, asset TEXT, "
            "impact TEXT, remediation TEXT, retest_status TEXT, "
            "evidence_ids_json TEXT, created_at TEXT)"
        )
        for fid, raw in (("f1", '["proof:1"]'), ("f2", '["proof:2"]')):
            self.db.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (fid, "client-A", "engagement-lab", "Example", "low",
                 "local-lab", "Example impact", "Example fix",
                 "not_tested", raw, "2026-10-12T00:00:00Z")
            )

    def rows(self):
        return self.db.execute(
            "SELECT * FROM findings ORDER BY finding_id"
        ).fetchall()

    def test_real_mapper_preserves_evidence_order(self):
        result = checked_findings_batch(self.rows())
        self.assertEqual([type(x) for x in result], [FindingRecord] * 2)
        self.assertEqual([x.evidence_ids for x in result],
                         [("proof:1",), ("proof:2",)])

    def test_late_invalid_json_rejects_before_mapping(self):
        self.db.execute(
            "UPDATE findings SET evidence_ids_json='null' WHERE finding_id='f2'"
        )
        with patch.object(batch, "checked_finding_from_row") as mapper:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                checked_findings_batch(self.rows())
            mapper.assert_not_called()
        self.assertEqual(self.rows()[1]["evidence_ids_json"], "null")


if __name__ == "__main__":
    unittest.main()
