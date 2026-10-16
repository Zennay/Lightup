"""Issue #639: synthetic SQLite nested entry admission on untouched #554 source.

Acceptance-only. Expected failures are *open* production-source contracts, not fixes.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class NestedPersistedScopeAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "scope-639.db")
        self.operator = AccessContext("synthetic-639-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Fictional 639 Client")
        engagement = self.store.create_engagement(
            self.operator, client.client_id, "Offline entry-integrity fixture"
        )
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator, engagement.engagement_id,
            "Synthetic reviewer", "FICTION-639",
            ScopeDefinition(
                assets=("app.example.invalid",),
                excluded_assets=("excluded.example.invalid",),
                allowed_capabilities=("web-baseline",),
                max_risk=RiskLevel.STANDARD,
            ),
            now - timedelta(hours=1), now + timedelta(hours=1),
        )
        self.original = self._snapshot()

    def _snapshot(self):
        with self.store._connect() as con:
            row = con.execute(
                "SELECT assets_json,excluded_assets_json,allowed_capabilities_json "
                "FROM authorization_grants WHERE grant_id=?",
                (self.grant.grant_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return tuple(row[key] for key in (
            "assets_json", "excluded_assets_json", "allowed_capabilities_json"
        ))

    def _mutate(self, column, json_payload):
        self.assertIn(column, (
            "assets_json", "excluded_assets_json", "allowed_capabilities_json"
        ))
        # Constant checked column name; payload is fictional and parameterized.
        with self.store._connect() as con:
            con.execute(
                f"UPDATE authorization_grants SET {column}=? WHERE grant_id=?",
                (json_payload, self.grant.grant_id),
            )
        before = self._snapshot()
        return before

    def _assert_deny_unchanged(self, column, json_payload):
        before = self._mutate(column, json_payload)
        try:
            resolved = self.store.resolve_authorization_for_execution(self.grant)
        except Exception as exc:
            self.fail("authorization resolution leaked an exception: " + type(exc).__name__)
        self.assertIsNone(resolved, "corrupt durable scope must never authorize execution")
        self.assertEqual(self._snapshot(), before, "do not normalize/overwrite evidence")

    def _classify_source(self, column, payload):
        before = self._mutate(column, payload)
        try:
            value = self.store.resolve_authorization_for_execution(self.grant)
        except Exception as exc:
            outcome = "raised:" + type(exc).__name__
        else:
            outcome = "granted" if value is not None else "denied"
        self.assertEqual(self._snapshot(), before)
        return outcome

    def test_unmodified_canonical_grant_resolves(self):
        live = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(live)
        self.assertEqual(live.grant_id, self.grant.grant_id)
        self.assertEqual(self._snapshot(), self.original)

    def test_outer_null_json_refused_without_write(self):
        self._assert_deny_unchanged("assets_json", "null")

    def test_outer_object_json_refused_without_write(self):
        self._assert_deny_unchanged("excluded_assets_json", '{"unexpected":true}')

    def test_scalar_capabilities_json_refused_without_write(self):
        self._assert_deny_unchanged("allowed_capabilities_json", '"web-baseline"')

    @unittest.expectedFailure  # OPEN: original #554 source reconstructs nullable entries
    def test_mixed_allowlist_null_must_not_resolve(self):
        self._assert_deny_unchanged(
            "assets_json", '["app.example.invalid",null]'
        )

    @unittest.expectedFailure  # OPEN: original #554 source accepts non-string exclusions
    def test_mixed_excluded_asset_false_must_not_resolve(self):
        self._assert_deny_unchanged(
            "excluded_assets_json", '["excluded.example.invalid",false]'
        )

    @unittest.expectedFailure  # OPEN: unhashable capability reaches registry.get
    def test_mixed_capabilities_object_must_not_leak_type_error(self):
        self._assert_deny_unchanged(
            "allowed_capabilities_json", '["web-baseline",{}]'
        )

    def test_exact_original_source_red_replay_witness(self):
        """Ordinary PASS oracle: no unrelated exception can fake a source-RED."""
        cases = (
            ("assets_json", '["app.example.invalid",null]', "granted"),
            ("excluded_assets_json", '["excluded.example.invalid",false]', "granted"),
            ("allowed_capabilities_json", '["web-baseline",{}]', "raised:TypeError"),
        )
        for column, payload, expected in cases:
            with self.subTest(column=column):
                # Restore synthetic fixture between cases; other columns stay canonical.
                with self.store._connect() as con:
                    con.execute(
                        "UPDATE authorization_grants SET "
                        "assets_json=?,excluded_assets_json=?,allowed_capabilities_json=? "
                        "WHERE grant_id=?",
                        (*self.original, self.grant.grant_id),
                    )
                self.assertEqual(self._classify_source(column, payload), expected)


if __name__ == "__main__":
    unittest.main()
