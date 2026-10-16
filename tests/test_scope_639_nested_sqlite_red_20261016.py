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
from lightup.persisted_scope_entries_639 import review_persisted_scope_entries


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


    def test_invalid_json_array_tail_refused(self):
        self._assert_deny_unchanged("assets_json", '["app.example.invalid",]')

    def test_sqlite_nontext_blob_scope_refused(self):
        self._assert_deny_unchanged("assets_json", bytes((0, 255)))

    def test_sqlite_numeric_scope_column_refused(self):
        self._assert_deny_unchanged("excluded_assets_json", 7)

    def test_empty_exclusions_remain_canonical(self):
        before = self._mutate("excluded_assets_json", "[]")
        live = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(live)
        self.assertEqual(live.scope.excluded_assets, ())
        self.assertEqual(self._snapshot(), before)

    @unittest.expectedFailure  # OPEN: no exact nested entry admission
    def test_empty_asset_scope_must_not_resolve(self):
        self._assert_deny_unchanged("assets_json", "[]")

    @unittest.expectedFailure  # OPEN: mixed blank identity still accepted
    def test_mixed_blank_asset_must_not_resolve(self):
        self._assert_deny_unchanged(
            "assets_json", '["app.example.invalid","   "]'
        )

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


    @unittest.expectedFailure  # OPEN: malformed assets cannot leave resolver
    def test_mixed_numeric_asset_must_never_leave_resolver(self):
        self._assert_deny_unchanged(
            "assets_json", '["app.example.invalid",123]'
        )

    @unittest.expectedFailure  # OPEN: malformed exclusions cannot leave resolver
    def test_mixed_boolean_exclusion_must_never_leave_resolver(self):
        self._assert_deny_unchanged(
            "excluded_assets_json", '["excluded.example.invalid",false]'
        )

    def test_legacy_numeric_asset_can_throw_in_memory_asset_matcher(self):
        """Observed source defect: no network/handler, only local ScopeDefinition."""
        before = self._mutate("assets_json", '["app.example.invalid",123]')
        leaked = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(leaked, "strict baseline changed: reassess open REDs")
        self.assertEqual(leaked.scope.assets, ("app.example.invalid", 123))
        with self.assertRaisesRegex(AttributeError, "strip"):
            leaked.scope.allows_asset("app.example.invalid")
        self.assertEqual(self._snapshot(), before)

    def test_legacy_boolean_exclusion_can_throw_in_memory_asset_matcher(self):
        """Observed source defect: exclusion check handles non-string as a value."""
        before = self._mutate(
            "excluded_assets_json", '["excluded.example.invalid",false]'
        )
        leaked = self.store.resolve_authorization_for_execution(self.grant)
        self.assertIsNotNone(leaked, "strict baseline changed: reassess open REDs")
        self.assertEqual(
            leaked.scope.excluded_assets, ("excluded.example.invalid", False)
        )
        with self.assertRaisesRegex(AttributeError, "strip"):
            leaked.scope.allows_asset("app.example.invalid")
        self.assertEqual(self._snapshot(), before)

    @unittest.expectedFailure  # OPEN: nonblank exact exclusion entry missing
    def test_blank_exclusion_must_not_resolve(self):
        self._assert_deny_unchanged(
            "excluded_assets_json", '["excluded.example.invalid","   "]'
        )

    @unittest.expectedFailure  # OPEN: nested object asset still reaches grant
    def test_nested_object_asset_must_not_resolve(self):
        self._assert_deny_unchanged(
            "assets_json", '["app.example.invalid",{}]'
        )

    def test_same_persisted_row_reviewer_blocks_original_source_leaks(self):
        """Functional handoff: same raw SQLite snapshot, zero grant promotion.

        Ordinary PASS source reproduction must not depend on an XFAIL marker.
        It proves the pure review rejects original source-authority leaks and
        the crash case without another read in the pure helper itself.
        """
        cases = (
            ("assets_json", '["app.example.invalid",null]', "granted"),
            ("assets_json", '["app.example.invalid",{}]', "granted"),
            ("excluded_assets_json", '["excluded.example.invalid","   "]', "granted"),
            ("excluded_assets_json", '["excluded.example.invalid",false]', "granted"),
            ("allowed_capabilities_json", '["web-baseline",{}]', "raised:TypeError"),
        )
        for column, payload, original_behavior in cases:
            with self.subTest(column=column, payload=payload):
                with self.store._connect() as con:
                    con.execute(
                        "UPDATE authorization_grants SET "
                        "assets_json=?,excluded_assets_json=?,allowed_capabilities_json=? "
                        "WHERE grant_id=?",
                        (*self.original, self.grant.grant_id),
                    )
                before = self._mutate(column, payload)
                self.assertIsNone(
                    review_persisted_scope_entries(
                        assets_json=before[0],
                        excluded_assets_json=before[1],
                        allowed_capabilities_json=before[2],
                    ),
                    "malformed original SQLite row must be held before any grant",
                )
                # Separate old-source observation: NOT an execution resolver,
                # no permission assertion and no target-capable handler.
                try:
                    current = self.store.resolve_authorization_for_execution(self.grant)
                except Exception as exc:
                    behavior = "raised:" + type(exc).__name__
                else:
                    behavior = "granted" if current is not None else "denied"
                self.assertEqual(behavior, original_behavior)
                self.assertEqual(before, self._snapshot())

    def test_same_persisted_row_reviewer_preserves_canonical_grant_shape(self):
        before = self._snapshot()
        preview = review_persisted_scope_entries(
            assets_json=before[0],
            excluded_assets_json=before[1],
            allowed_capabilities_json=before[2],
        )
        self.assertIsNotNone(preview)
        self.assertEqual(preview.assets, self.grant.scope.assets)
        self.assertEqual(preview.excluded_assets, self.grant.scope.excluded_assets)
        self.assertEqual(preview.allowed_capabilities, self.grant.scope.allowed_capabilities)
        self.assertFalse(hasattr(preview, "grant_id"))
        self.assertFalse(hasattr(preview, "is_current"))
        self.assertEqual(before, self._snapshot())

    def test_opt_in_same_row_resolver_seam_denies_corruption(self):
        """Offline-only preview of owner integration: no permanent patch.

        The installed resolver stays unchanged. During this one test only,
        _grant_from_row receives its already-fetched joined sqlite3.Row and
        refuses bad entries *before* any grant reconstruction. The existing
        resolver catches ValueError and fails closed without handler/network.
        """
        from unittest.mock import patch

        original_parse = self.store._grant_from_row
        seen = []

        def checked_from_same_row(row):
            self.assertEqual(
                tuple(row[column] for column in (
                    "assets_json", "excluded_assets_json",
                    "allowed_capabilities_json",
                )),
                self._snapshot(),
                "guard must inspect the identical raw row, never a second query",
            )
            seen.append(row["grant_id"])
            if review_persisted_scope_entries(
                assets_json=row["assets_json"],
                excluded_assets_json=row["excluded_assets_json"],
                allowed_capabilities_json=row["allowed_capabilities_json"],
            ) is None:
                raise ValueError("synthetic invalid nested grant scope")
            return original_parse(row)

        cases = (
            ("assets_json", "[]"),
            ("assets_json", '["app.example.invalid",null]'),
            ("assets_json", '["app.example.invalid",{}]'),
            ("assets_json", '["app.example.invalid",123]'),
            ("excluded_assets_json", '["excluded.example.invalid",false]'),
            ("excluded_assets_json", '["excluded.example.invalid","   "]'),
            ("allowed_capabilities_json", '["web-baseline",{}]'),
        )
        with patch.object(self.store, "_grant_from_row", side_effect=checked_from_same_row):
            # Keep the exact old normal policy success intact.
            self.assertIsNotNone(self.store.resolve_authorization_for_execution(self.grant))
            for column, payload in cases:
                with self.subTest(column=column, payload=payload):
                    with self.store._connect() as con:
                        con.execute(
                            "UPDATE authorization_grants SET "
                            "assets_json=?,excluded_assets_json=?,allowed_capabilities_json=? "
                            "WHERE grant_id=?",
                            (*self.original, self.grant.grant_id),
                        )
                    before = self._mutate(column, payload)
                    self.assertIsNone(
                        self.store.resolve_authorization_for_execution(self.grant),
                        "same-row shape rejection should deny, not crash or grant",
                    )
                    self.assertEqual(self._snapshot(), before)
            self.assertEqual(len(seen), len(cases) + 1)
            self.assertTrue(all(value == self.grant.grant_id for value in seen))

        # The original source is NOT repaired by the temporary test patch.
        before = self._mutate("assets_json", '["app.example.invalid",null]')
        self.assertIsNotNone(self.store.resolve_authorization_for_execution(self.grant))
        self.assertEqual(self._snapshot(), before)

    def test_exact_original_source_red_replay_witness(self):
        """Ordinary PASS oracle: no unrelated exception can fake a source-RED."""
        cases = (
            ("assets_json", '["app.example.invalid",null]', "granted"),
            ("assets_json", "[]", "granted"),
            ("assets_json", '["app.example.invalid","   "]', "granted"),
            ("excluded_assets_json", '["excluded.example.invalid",false]', "granted"),
            ("assets_json", '["app.example.invalid",{}]', "granted"),
            ("excluded_assets_json", '["excluded.example.invalid","   "]', "granted"),
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
