"""Offline-only acceptance for the optional non-authorizing #639 entry reviewer."""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition
from scope_639_strict_entry_reference import (
    ReviewedScopeEntries, review_scope_entries,
)


class StrictEntryReferenceTest(unittest.TestCase):
    def review(self, assets='["app.example.invalid"]', exclusions='[]',
               capabilities='["web-baseline"]'):
        return review_scope_entries(
            assets_json=assets, excluded_assets_json=exclusions,
            allowed_capabilities_json=capabilities,
        )

    def test_canonical_snapshot_preserves_exact_text(self):
        expected = ReviewedScopeEntries(
            ("App.Example.Invalid", "app.example.invalid"),
            ("EXCLUDED.example.invalid",), ("web-baseline",),
        )
        self.assertEqual(
            self.review(
                '["App.Example.Invalid","app.example.invalid"]',
                '["EXCLUDED.example.invalid"]',
            ), expected,
        )

    def test_empty_exclusions_are_allowed(self):
        value = self.review()
        self.assertIsNotNone(value)
        self.assertEqual(value.excluded_assets, ())

    def test_result_is_immutable_and_not_a_grant(self):
        value = self.review()
        self.assertIsNotNone(value)
        self.assertIs(type(value.assets), tuple)
        with self.assertRaises(AttributeError):
            value.assets = ("other.example.invalid",)
        self.assertFalse(hasattr(value, "grant_id"))
        self.assertFalse(hasattr(value, "is_current"))
        self.assertFalse(hasattr(value, "allowed"))

    def test_mandatory_arrays_cannot_be_empty(self):
        for field in ("assets", "capabilities"):
            with self.subTest(field=field):
                if field == "assets":
                    self.assertIsNone(self.review(assets="[]"))
                else:
                    self.assertIsNone(self.review(capabilities="[]"))

    def test_outer_json_shapes_fail_closed(self):
        for payload in ("null", "true", "false", "0", '""', "{}", 
                        '{"spoof":"app.example.invalid"}', "not-json",
                        '["bad",]'):
            for field in ("assets", "exclusions", "capabilities"):
                with self.subTest(payload=payload, field=field):
                    kwargs = {field: payload}
                    self.assertIsNone(self.review(**kwargs))

    def test_nested_invalid_element_types_fail_closed(self):
        bad_elements = ("null", "false", "true", "3", "-1",
                        "3.14159", "{}", "[]")
        for element in bad_elements:
            for field, original in (
                ("assets", "app.example.invalid"),
                ("exclusions", "excluded.example.invalid"),
                ("capabilities", "web-baseline"),
            ):
                with self.subTest(element=element, field=field):
                    values = json.dumps([original], separators=(",", ":"))
                    values = values[:-1] + "," + element + "]"
                    self.assertIsNone(self.review(**{field: values}))

    def test_blank_strings_fail_closed_in_every_array(self):
        for blank in ("", " ", "\t", "\n", "\u2003"):
            for field in ("assets", "exclusions", "capabilities"):
                with self.subTest(blank=repr(blank), field=field):
                    payload = json.dumps(["valid", blank])
                    self.assertIsNone(self.review(**{field: payload}))

    def test_no_filtering_of_bad_items_into_partial_scope(self):
        self.assertIsNone(self.review(assets='["app.example.invalid",null]'))
        self.assertIsNone(
            self.review(capabilities='["web-baseline",{"role":"operator"}]')
        )

    def test_exact_outer_type_before_side_effectful_str_subclass(self):
        class HostileString(str):
            compare_calls = 0
            strip_calls = 0

            def __eq__(self, other):
                self.compare_calls += 1
                return True

            def strip(self, *args, **kwargs):
                self.strip_calls += 1
                return '["forged.example.invalid"]'

        fake = HostileString('["app.example.invalid"]')
        self.assertIsNone(self.review(assets=fake))
        self.assertEqual(fake.compare_calls, 0)
        self.assertEqual(fake.strip_calls, 0)

    def test_non_text_inputs_have_no_conversion_callbacks(self):
        class HostileObject:
            str_calls = 0
            repr_calls = 0

            def __str__(self):
                self.str_calls += 1
                return '["app.example.invalid"]'

            def __repr__(self):
                self.repr_calls += 1
                return '["app.example.invalid"]'

        forged = HostileObject()
        for field in ("assets", "exclusions", "capabilities"):
            self.assertIsNone(self.review(**{field: forged}))
        self.assertEqual(forged.str_calls, 0)
        self.assertEqual(forged.repr_calls, 0)

    def test_raw_sqlite_blob_integer_and_null_fail_closed(self):
        for value in (bytes((255, 254)), 4, None, True, 1.25):
            with self.subTest(type=type(value).__name__):
                self.assertIsNone(self.review(assets=value))

    def test_deeply_nested_malformed_json_fails_closed(self):
        self.assertIsNone(self.review(assets="[" * 2500 + "0" + "]" * 2500))


    def test_seeded_mixed_corruption_900_cases_all_hold(self):
        """Deterministic hostile nested entries cannot be partially accepted."""
        from random import Random

        rng = Random(639)
        bad = (None, False, True, 0, -1, 2.75, [], {},
               "", " ", "\t", "\u2003", ["nested"], {"capability": "web-baseline"})
        entries = (
            ("assets", "app.example.invalid"),
            ("exclusions", "excluded.example.invalid"),
            ("capabilities", "web-baseline"),
        )
        for index in range(300):
            corrupt = rng.choice(bad)
            for field, canonical in entries:
                with self.subTest(index=index, field=field):
                    payload = json.dumps([canonical, corrupt], separators=(",", ":"))
                    self.assertIsNone(
                        self.review(**{field: payload}),
                        "one invalid nested item cannot be dropped or coerced",
                    )


    def test_review_never_opens_files_sockets_sqlite_or_processes(self):
        """The non-authorizing reviewer has zero IO capabilities."""
        import builtins
        import os
        import socket
        import sqlite3
        import subprocess
        from unittest.mock import patch

        def reject_io(*args, **kwargs):
            raise AssertionError("scope entry review attempted forbidden IO")

        with (
            patch.object(builtins, "open", side_effect=reject_io),
            patch.object(os, "open", side_effect=reject_io),
            patch.object(socket, "socket", side_effect=reject_io),
            patch.object(sqlite3, "connect", side_effect=reject_io),
            patch.object(subprocess, "Popen", side_effect=reject_io),
        ):
            self.assertEqual(
                self.review().assets, ("app.example.invalid",)
            )
            self.assertIsNone(
                self.review(assets='["app.example.invalid",null]')
            )

    def test_test_shim_exercises_real_src_helper(self):
        """Require direct identity; CI must not pass on an orphan mock copy."""
        from lightup.persisted_scope_entries_639 import (
            PersistedScopeEntries,
            review_persisted_scope_entries,
        )

        self.assertIs(review_scope_entries, review_persisted_scope_entries)
        self.assertIs(ReviewedScopeEntries, PersistedScopeEntries)
        self.assertIs(
            type(self.review()),
            PersistedScopeEntries,
        )
        self.assertFalse(hasattr(review_persisted_scope_entries, "authorize"))

    def test_scope_shape_never_implies_tenant_or_consent(self):
        """A valid shape is a literal snapshot, not an authorization record."""
        for asset in (
            "app.example.invalid",
            "other.example.invalid",
            "third.example.invalid",
        ):
            with self.subTest(asset=asset):
                result = self.review(assets=json.dumps([asset]))
                self.assertEqual(result.assets, (asset,))
                for attribute in (
                    "tenant_id", "client_id", "engagement_id", "grant_id",
                    "approved_by", "reference", "revoked_at", "is_current",
                ):
                    self.assertFalse(hasattr(result, attribute))


    def test_oversized_json_rejected_before_any_decode_for_every_field(self):
        """Do not hand attacker-controlled giant rows to json.loads."""
        from unittest.mock import patch
        from lightup.persisted_scope_entries_639 import MAX_SCOPE_JSON_CHARS

        payload = " " * (MAX_SCOPE_JSON_CHARS + 1)
        original_loads = json.loads

        def refuse_oversized_decode(value):
            self.assertNotEqual(value, payload, "oversized JSON was parsed")
            return original_loads(value)

        for field in ("assets", "exclusions", "capabilities"):
            with self.subTest(field=field):
                with patch(
                    "lightup.persisted_scope_entries_639.json.loads",
                    side_effect=refuse_oversized_decode,
                ):
                    self.assertIsNone(self.review(**{field: payload}))

    def test_maximum_entry_size_is_inclusive_and_one_more_refused(self):
        from lightup.persisted_scope_entries_639 import MAX_SCOPE_ENTRY_CHARS

        allowed = "a" * MAX_SCOPE_ENTRY_CHARS
        self.assertEqual(self.review(assets=json.dumps([allowed])).assets, (allowed,))
        for field in ("assets", "exclusions", "capabilities"):
            with self.subTest(field=field):
                payload = json.dumps(["valid", "b" * (MAX_SCOPE_ENTRY_CHARS + 1)])
                self.assertIsNone(self.review(**{field: payload}))

    def test_list_entry_count_limit_inclusive_for_each_field(self):
        from lightup.persisted_scope_entries_639 import MAX_SCOPE_ENTRIES

        for field in ("assets", "exclusions", "capabilities"):
            with self.subTest(field=field):
                valid = ["valid"] * MAX_SCOPE_ENTRIES
                review = self.review(**{field: json.dumps(valid)})
                self.assertIsNotNone(review)
                attr = {"assets": "assets", "exclusions": "excluded_assets",
                        "capabilities": "allowed_capabilities"}[field]
                self.assertEqual(len(getattr(review, attr)), MAX_SCOPE_ENTRIES)
                denied = valid + ["over"]
                self.assertIsNone(self.review(**{field: json.dumps(denied)}))

    def test_oversized_mixed_row_does_not_return_partial_authority(self):
        from lightup.persisted_scope_entries_639 import MAX_SCOPE_ENTRIES

        valid = self.review()
        self.assertIsNotNone(valid)
        denied = self.review(
            assets='["app.example.invalid"]',
            exclusions='["excluded.example.invalid"]',
            capabilities=json.dumps(["web-baseline"] * (MAX_SCOPE_ENTRIES + 1)),
        )
        self.assertIsNone(denied)
        self.assertEqual(self.review(), valid)


    def test_real_sqlite_snapshot_corruption_review_has_no_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DomainStore(Path(tmp) / "scope639-review.db")
            op = AccessContext("fiction-operator", Role.OPERATOR)
            client = store.create_client(op, "Fictional entry-review tenant")
            engagement = store.create_engagement(op, client.client_id, "offline")
            now = datetime.now(timezone.utc)
            grant = store.record_authorization_grant(
                op, engagement.engagement_id,
                "Fictional reviewer", "FICTION-ONLY",
                ScopeDefinition(
                    ("app.example.invalid",), RiskLevel.STANDARD,
                    ("web-baseline",), (),
                ),
                now - timedelta(hours=1), now + timedelta(hours=1),
            )

            def stored():
                with store._connect() as con:
                    row = con.execute(
                        "SELECT assets_json,excluded_assets_json,"
                        "allowed_capabilities_json FROM authorization_grants "
                        "WHERE grant_id=?", (grant.grant_id,),
                    ).fetchone()
                self.assertIsNotNone(row)
                return tuple(row)

            original = stored()
            self.assertEqual(
                self.review(*original),  # positional wrapper values
                ReviewedScopeEntries(("app.example.invalid",), (), ("web-baseline",)),
            )
            with store._connect() as con:
                con.execute(
                    "UPDATE authorization_grants SET assets_json=? WHERE grant_id=?",
                    ('["app.example.invalid",123]', grant.grant_id),
                )
            corrupt = stored()
            self.assertIsNone(self.review(*corrupt))
            self.assertEqual(stored(), corrupt)
            self.assertNotEqual(corrupt, original)


if __name__ == "__main__":
    unittest.main()
