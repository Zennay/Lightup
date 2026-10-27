"""#877 real disposable SQLite producer-read characterization and guarded decode.

All assets are synthetic; this read-only preflight is not wired into grant or
approval issuance. Expected failures reveal current _request_from_row gaps.
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.request_assets_shape_optin import checked_requested_assets_json


class PolymorphicString(str):
    pass


class PersistedRequestAssetsIssue877(unittest.TestCase):
    def setUp(self):
        fixture = tempfile.TemporaryDirectory()
        self.addCleanup(fixture.cleanup)
        self.database = Path(fixture.name) / "request877.db"
        self.store = DomainStore(self.database)
        self.operator = AccessContext("scope-877-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Synthetic 877 client")
        other = self.store.create_client(self.operator, "Synthetic other client")
        self.client = AccessContext("requester-877", Role.CLIENT_ADMIN, client.client_id)
        self.foreign = AccessContext("requester-foreign", Role.CLIENT_ADMIN, other.client_id)
        self.request = self.store.submit_assessment_request(
            self.client, ("alpha.example.test", "beta.example.test"),
            AssessmentMode.ANALYSIS_ONLY, RiskLevel.ANALYSIS_ONLY,
            "offline acceptance fixture",
        )

    def replace_json(self, raw):
        with sqlite3.connect(self.database) as con:
            con.execute(
                "UPDATE assessment_requests SET requested_assets_json=? WHERE request_id=?",
                (raw, self.request.request_id),
            )

    def raw_from_sqlite(self):
        with sqlite3.connect(self.database) as con:
            return con.execute(
                "SELECT requested_assets_json FROM assessment_requests WHERE request_id=?",
                (self.request.request_id,),
            ).fetchone()[0]

    def source(self):
        return self.store.get_assessment_request(self.operator, self.request.request_id)

    @unittest.expectedFailure
    def test_red_default_reader_must_reject_object_keys_as_assets(self):
        self.replace_json('{"alpha.example.test":"not an asset array"}')
        with self.assertRaises((ValueError, TypeError)):
            self.source()

    @unittest.expectedFailure
    def test_red_default_reader_must_reject_string_character_expansion(self):
        self.replace_json('"alpha.example.test"')
        with self.assertRaises((ValueError, TypeError)):
            self.source()

    @unittest.expectedFailure
    def test_red_default_reader_must_reject_mixed_type_assets(self):
        self.replace_json('["alpha.example.test", false, 17, null]')
        with self.assertRaises((ValueError, TypeError)):
            self.source()

    @unittest.expectedFailure
    def test_red_default_reader_must_reject_empty_assets(self):
        self.replace_json('[]')
        with self.assertRaises((ValueError, TypeError)):
            self.source()

    @unittest.expectedFailure
    def test_red_default_reader_must_reject_blank_assets(self):
        self.replace_json('["alpha.example.test", "  "]')
        with self.assertRaises((ValueError, TypeError)):
            self.source()

    def test_real_canonical_sqlite_roundtrip_is_unchanged(self):
        record = self.source()
        self.assertEqual(record.requested_assets, ("alpha.example.test", "beta.example.test"))
        self.assertEqual(checked_requested_assets_json(self.raw_from_sqlite()), record.requested_assets)

    def test_real_producer_rejection_canary_preserves_durable_row(self):
        for raw in ('{"one":"two"}', '"string"', '[]', '["a",null]', '[" "]'):
            with self.subTest(raw=raw):
                self.replace_json(raw)
                before = self.raw_from_sqlite()
                with self.assertRaises(ValueError):
                    checked_requested_assets_json(before)
                self.assertEqual(self.raw_from_sqlite(), before)

    def test_guard_rejects_malformed_json_without_echo(self):
        for raw in ('{', '["unterminated]', 'null', 'true', '123', '{}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError) as rejected:
                checked_requested_assets_json(raw)
            self.assertNotIn(raw, str(rejected.exception))

    def test_guard_rejects_nonbuiltin_json_text_and_polymorphism(self):
        for raw in (None, 0, [], {}, False, b'["alpha"]', PolymorphicString('["alpha"]')):
            with self.subTest(value=type(raw).__name__), self.assertRaises(ValueError):
                checked_requested_assets_json(raw)

    def test_guard_does_not_normalize_sort_or_deduplicate_admitted_assets(self):
        raw = json.dumps(["Beta.example.test", "alpha.example.test", "Beta.example.test"])
        self.assertEqual(checked_requested_assets_json(raw), (
            "Beta.example.test", "alpha.example.test", "Beta.example.test",
        ))

    def test_guard_does_not_strip_nonempty_admitted_string(self):
        self.assertEqual(checked_requested_assets_json('[" alpha.example.test "]'),
                         (" alpha.example.test ",))

    def test_guard_rejects_nested_array_and_object_values(self):
        for raw in ('[["alpha.example.test"]]', '[{"url":"alpha.example.test"}]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                checked_requested_assets_json(raw)

    def test_selector_tenant_isolation_remains_independent(self):
        with self.assertRaises(TenantIsolationError):
            self.store.get_assessment_request(self.foreign, self.request.request_id)

    def test_guard_creates_no_grants_and_does_not_mutate_requests(self):
        raw = self.raw_from_sqlite()
        selected = checked_requested_assets_json(raw)
        self.assertEqual(selected, ("alpha.example.test", "beta.example.test"))
        with sqlite3.connect(self.database) as con:
            n_grants = con.execute("SELECT COUNT(*) FROM authorization_grants").fetchone()[0]
            n_engagements = con.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]
        self.assertEqual(n_grants, 0)
        self.assertEqual(n_engagements, 0)
        self.assertEqual(self.raw_from_sqlite(), raw)


if __name__ == "__main__":
    unittest.main()
