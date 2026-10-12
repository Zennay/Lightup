"""Opt-in checked row boundary regressions (#856/#886), disposable SQLite only.

This isolates a deliberately minimal mapper: it is NOT a full DomainStore,
authorization, deployed read path, or permanent CI integration test.
"""
from __future__ import annotations

import importlib
import json
import sqlite3
import sys
import types
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class FindingRecord:
    evidence_ids: tuple[str, ...]


class DomainStore:
    calls = 0
    reorder = False

    @staticmethod
    def _finding_from_row(row):
        DomainStore.calls += 1
        refs = tuple(json.loads(row["evidence_ids_json"]))
        if DomainStore.reorder:
            refs = refs[::-1]
        return FindingRecord(refs)


class CheckedRowBoundaryW31Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_domain = sys.modules.get("lightup.domain")
        cls.original_adapter = sys.modules.get("lightup.finding_row_checked_optin_w30")
        fake = types.ModuleType("lightup.domain")
        fake.DomainStore = DomainStore
        fake.FindingRecord = FindingRecord
        sys.modules["lightup.domain"] = fake
        sys.modules.pop("lightup.finding_row_checked_optin_w30", None)
        cls.adapter = importlib.import_module("lightup.finding_row_checked_optin_w30")

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("lightup.finding_row_checked_optin_w30", None)
        if cls.original_adapter is not None:
            sys.modules["lightup.finding_row_checked_optin_w30"] = cls.original_adapter
        if cls.original_domain is None:
            sys.modules.pop("lightup.domain", None)
        else:
            sys.modules["lightup.domain"] = cls.original_domain

    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE findings (tenant TEXT NOT NULL, evidence_ids_json)")
        self.db.executemany("INSERT INTO findings VALUES (?, ?)", [
            ("A", '["evidence:A1", "evidence:A2"]'),
            ("B", '["evidence:B1"]'),
        ])
        self.addCleanup(self.db.close)
        DomainStore.calls = 0
        DomainStore.reorder = False

    def row(self, tenant):
        return self.db.execute("SELECT * FROM findings WHERE tenant=?", (tenant,)).fetchone()

    def raw(self, tenant):
        return self.row(tenant)["evidence_ids_json"]

    def put(self, tenant, raw):
        self.db.execute("UPDATE findings SET evidence_ids_json=? WHERE tenant=?", (raw, tenant))

    def assert_denied_without_mapper(self, raw):
        self.put("A", raw)
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            self.adapter.checked_finding_from_row(self.row("A"))
        self.assertEqual(DomainStore.calls, 0)
        self.assertEqual(self.raw("A"), raw)

    def test_valid_canonical_refs_are_ordered_unmodified(self):
        raw = '["évidence:first", "evidence:second ", "evidence:third"]'
        self.put("A", raw)
        result = self.adapter.checked_finding_from_row(self.row("A"))
        self.assertEqual(result.evidence_ids, ("évidence:first", "evidence:second ", "evidence:third"))
        self.assertEqual(DomainStore.calls, 1)
        self.assertEqual(self.raw("A"), raw)

    def test_corrupt_shapes_never_reach_legacy_mapper(self):
        for raw in ('null', '17', 'true', '"ab"', '{"x": 1}', '["a", null]',
                    '["a", "a"]', '["  "]', '["a"', '["a", ["b"]]',
                    '[NaN]', '[Infinity]', '[-Infinity]', '["a", "\\u0061"]',
                    '["\\ud800"]', '[' * 2048 + '"a"' + ']' * 2048):
            with self.subTest(raw=raw[:35]):
                DomainStore.calls = 0
                self.assert_denied_without_mapper(raw)

    def test_invalid_sqlite_column_types_never_reach_mapper(self):
        for raw in (None, 12, 2.5, b'["a"]'):
            with self.subTest(type=type(raw).__name__):
                DomainStore.calls = 0
                self.assert_denied_without_mapper(raw)

    def test_missing_evidence_column_is_generic_denial(self):
        row = self.db.execute("SELECT tenant FROM findings WHERE tenant='A'").fetchone()
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            self.adapter.checked_finding_from_row(row)
        self.assertEqual(DomainStore.calls, 0)

    def test_non_sqlite_row_is_generic_denial(self):
        for row in (None, {}, [], '["a"]'):
            with self.subTest(type=type(row).__name__):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    self.adapter.checked_finding_from_row(row)
        self.assertEqual(DomainStore.calls, 0)

    def test_mapper_disagreement_is_generic_denial_without_write(self):
        before = self.raw("A")
        DomainStore.reorder = True
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            self.adapter.checked_finding_from_row(self.row("A"))
        self.assertEqual(DomainStore.calls, 1)
        self.assertEqual(self.raw("A"), before)

    def test_corrupt_tenant_does_not_modify_other_tenant(self):
        before_b = self.raw("B")
        self.assert_denied_without_mapper('"ab"')
        self.assertEqual(self.raw("B"), before_b)
        self.assertEqual(self.adapter.checked_finding_from_row(self.row("B")).evidence_ids, ("evidence:B1",))
        self.assertEqual(DomainStore.calls, 1)

    def test_empty_manual_and_exact_reference_count_boundary(self):
        for refs in ([], ["ref:" + str(i) for i in range(128)]):
            raw = json.dumps(refs)
            self.put("A", raw)
            self.assertEqual(self.adapter.checked_finding_from_row(self.row("A")).evidence_ids, tuple(refs))
            self.assertEqual(self.raw("A"), raw)
        DomainStore.calls = 0
        self.assert_denied_without_mapper(json.dumps(["ref:" + str(i) for i in range(129)]))

    def test_utf8_byte_boundary_denied_before_mapper(self):
        self.put("A", json.dumps(["🚀" * 1024]))
        self.assertEqual(self.adapter.checked_finding_from_row(self.row("A")).evidence_ids, ("🚀" * 1024,))
        DomainStore.calls = 0
        self.assert_denied_without_mapper(json.dumps(["🚀" * 1025]))

    def test_default_mapper_gap_remains_visible(self):
        self.put("A", '"ab"')
        self.assertEqual(DomainStore._finding_from_row(self.row("A")).evidence_ids, ("a", "b"))
        DomainStore.calls = 0
        self.assert_denied_without_mapper('"ab"')


if __name__ == "__main__":
    unittest.main()
