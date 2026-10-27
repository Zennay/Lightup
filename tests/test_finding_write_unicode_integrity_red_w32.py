"""Write-side Finding evidence Unicode integrity regression; disposable DB only.

Expected failures document currently missing #851/#857 write-time admission.
They MUST NOT be converted into passing tests by weakening assertions.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.models import Severity


class EvidenceWriteUnicodeBoundaryW32(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = DomainStore(Path(temporary.name) / "disposable.db")
        self.operator = AccessContext("synthetic-evidence-w32", Role.OPERATOR)
        client = self.store.create_client(self.operator, "synthetic-only")
        self.engagement = self.store.create_engagement(
            self.operator, client.client_id, "synthetic-only"
        )

    def record(self, evidence):
        return self.store.record_finding(
            self.operator, self.engagement.engagement_id,
            "Synthetic evidence write", Severity.LOW, "offline.synthetic",
            "Inert demonstration", "Human-only remediation",
            evidence_ids=evidence,
        )

    def raw_rows(self):
        with self.store._connect() as connection:
            rows = connection.execute(
                "SELECT finding_id,evidence_ids_json FROM findings "
                "ORDER BY finding_id"
            ).fetchall()
        return tuple(tuple(row) for row in rows)

    def deny_without_sql_mutation(self, evidence):
        before = self.raw_rows()
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.record(evidence)
        self.assertEqual(self.raw_rows(), before)

    def test_canonical_unicode_references_keep_order(self):
        references = ("évidence:première", "evidence:second", "🛡 evidence:third")
        record = self.record(references)
        self.assertEqual(record.evidence_ids, references)
        stored = self.raw_rows()
        self.assertEqual(len(stored), 1)
        self.assertIn("vidence", stored[0][1])

    def test_empty_manual_evidence_tuple_remains_compatible(self):
        record = self.record(())
        self.assertEqual(record.evidence_ids, ())
        self.assertEqual(len(self.raw_rows()), 1)

    @unittest.expectedFailure
    def test_unanchored_combining_mark_rejected_preinsert_expected_red(self):
        self.deny_without_sql_mutation(("\u0301",))

    @unittest.expectedFailure
    def test_variation_selector_only_ref_rejected_expected_red(self):
        self.deny_without_sql_mutation(("\ufe0f",))

    @unittest.expectedFailure
    def test_bidi_format_only_ref_rejected_expected_red(self):
        self.deny_without_sql_mutation(("\u202e",))

    @unittest.expectedFailure
    def test_lone_surrogate_ref_rejected_expected_red(self):
        self.deny_without_sql_mutation(("\ud800",))

    @unittest.expectedFailure
    def test_oversized_reference_rejected_before_sql_expected_red(self):
        self.deny_without_sql_mutation(("evidence:" + ("x" * 4097),))

    @unittest.expectedFailure
    def test_nfkc_alias_reference_collision_rejected_expected_red(self):
        self.deny_without_sql_mutation(("évidence:alpha", "e\u0301vidence:alpha"))


if __name__ == "__main__":
    unittest.main()
