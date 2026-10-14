"""W33 real disposable-SQLite opt-in Finding write Unicode admission."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role, RoleError
from lightup.finding_write_unicode_guard_optin_w33 import (
    checked_written_evidence_references_w33,
    record_finding_checked_unicode_optin_w33,
)
from lightup.models import Severity


class OptinWriteUnicodeW33Tests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.store = DomainStore(Path(scratch.name) / "synthetic-only.db")
        self.operator = AccessContext("operator-w33", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "W33 synthetic client")
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "W33 synthetic engagement"
        )

    def rows(self):
        with self.store._connect() as con:
            return tuple(tuple(r) for r in con.execute(
                "SELECT finding_id,evidence_ids_json FROM findings ORDER BY finding_id"
            ).fetchall())

    def checked_write(self, refs=()):
        return record_finding_checked_unicode_optin_w33(
            self.store, self.operator, self.engagement.engagement_id,
            "Synthetic-only finding", Severity.LOW, "offline.synthetic",
            "No live impact", "Human-only remediation",
            evidence_ids=refs,
        )

    def test_ordinary_unicode_and_evidence_order_roundtrip(self):
        refs = ("évidence:alpha", "☃️:snow", "evidence:bravo")
        finding = self.checked_write(refs)
        self.assertEqual(finding.evidence_ids, refs)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(refs, checked_written_evidence_references_w33(refs))

    def test_manual_findings_keep_empty_evidence(self):
        finding = self.checked_write()
        self.assertEqual(finding.evidence_ids, ())
        self.assertEqual(len(self.rows()), 1)

    def test_no_visible_mark_format_or_surrogate_can_reach_writer(self):
        bad_refs = (
            ("\u0301",), ("\ufe0f",), ("\u202e",),
            ("a\u200bb",), ("\ud800",), ("e \u0301",),
            ("evidence:\u0301",), ("evidence:\ufe0f",),
            ("e\u034fvidence",),
        )
        for refs in bad_refs:
            with self.subTest(refs=repr(refs)):
                before = self.rows()
                with patch.object(self.store, "record_finding") as writer:
                    with self.assertRaisesRegex(ValueError, "write integrity"):
                        self.checked_write(refs)
                    writer.assert_not_called()
                self.assertEqual(before, self.rows())

    def test_nfkc_equivalent_reference_pairs_deny_atomically(self):
        pairs = (
            ("évidence:alpha", "e\u0301vidence:alpha"),
            ("evidence:ABC", "evidence:ＡＢＣ"),
        )
        for refs in pairs:
            with self.subTest(refs=refs):
                before = self.rows()
                with patch.object(self.store, "record_finding") as writer:
                    with self.assertRaisesRegex(ValueError, "write integrity"):
                        self.checked_write(refs)
                    writer.assert_not_called()
                self.assertEqual(before, self.rows())

    def test_one_reference_over_4096_utf8_bytes_denies_preinsert(self):
        refs = ("evidence:" + "é" * 2045,)
        self.assertGreater(len(refs[0].encode("utf8")), 4096)
        before = self.rows()
        with self.assertRaisesRegex(ValueError, "write integrity"):
            self.checked_write(refs)
        self.assertEqual(self.rows(), before)

    def test_json_serialization_inflation_denied_without_insert(self):
        refs = tuple(f"{i:03d}" + "é" * 1900 for i in range(60))
        self.assertTrue(all(len(s.encode("utf8")) <= 4096 for s in refs))
        before = self.rows()
        with self.assertRaisesRegex(ValueError, "write integrity"):
            self.checked_write(refs)
        self.assertEqual(self.rows(), before)

    def test_129_references_and_opaque_input_type_refused(self):
        class TupleSubclass(tuple):
            pass
        class StrSubclass(str):
            pass
        values = (
            [("canonical",)], TupleSubclass(("canonical",)),
            ("evidence", "evidence"), (StrSubclass("evidence"),),
            (" ",), tuple(f"evidence:{i}" for i in range(129)),
        )
        for refs in values:
            with self.subTest(refs_type=type(refs).__name__, count=len(refs)):
                before = self.rows()
                with self.assertRaisesRegex(ValueError, "write integrity"):
                    self.checked_write(refs)
                self.assertEqual(before, self.rows())

    def test_read_side_stores_canonical_identity_unchanged(self):
        refs = ("example:é", "example:é-two", "example:safe")
        result = self.checked_write(refs)
        self.assertEqual(result.evidence_ids, refs)
        stored = self.store.list_findings(
            self.operator, engagement_id=self.engagement.engagement_id
        )
        self.assertEqual(stored[0].evidence_ids, refs)

    def test_exact_4096_utf8_byte_reference_is_accepted(self):
        reference = "é" * 2048
        self.assertEqual(len(reference.encode("utf-8")), 4096)
        result = self.checked_write((reference,))
        self.assertEqual(result.evidence_ids, (reference,))
        self.assertEqual(len(self.rows()), 1)

    def test_exact_serialized_json_262144_bytes_is_accepted(self):
        import json
        references = tuple(
            f"{index:03d}" + ("x" * 2041) for index in range(128)
        )
        serialized = json.dumps(list(references)).encode("utf-8")
        self.assertEqual(len(serialized), 262144)
        record = self.checked_write(references)
        self.assertEqual(record.evidence_ids, references)
        self.assertEqual(len(self.rows()), 1)

    def test_one_serialized_json_byte_over_limit_never_reaches_writer(self):
        import json
        references = [
            f"{index:03d}" + ("x" * 2041) for index in range(128)
        ]
        references[-1] += "x"
        self.assertEqual(len(json.dumps(references).encode("utf-8")), 262145)
        before = self.rows()
        with patch.object(self.store, "record_finding") as writer:
            with self.assertRaisesRegex(ValueError, "write integrity"):
                self.checked_write(tuple(references))
            writer.assert_not_called()
        self.assertEqual(self.rows(), before)

    def test_existing_operator_role_checks_remain_in_force(self):
        client_context = AccessContext(
            "synthetic-client-user", Role.CLIENT_ADMIN, self.client.client_id
        )
        before = self.rows()
        with self.assertRaises(RoleError):
            record_finding_checked_unicode_optin_w33(
                self.store, client_context, self.engagement.engagement_id,
                "Synthetic-only", Severity.LOW, "offline.synthetic",
                "No live impact", "Human-only remediation",
                evidence_ids=("evidence:one",),
            )
        self.assertEqual(before, self.rows())


if __name__ == "__main__":
    unittest.main()
