"""Issue #376: independent HOLD-only asset-shape proof and open source REDs.

No public targets, handlers, grants for customers, or network I/O.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition
from lightup.scope_376_asset_identity_review import (
    AssetIdentityShapeReceipt, review_asset_identity_shape,
)


def _scope(assets=("fixture.example.test",), excluded=()):
    return ScopeDefinition(assets=assets, max_risk=RiskLevel.PASSIVE, excluded_assets=excluded)


class AssetShapeReview376(unittest.TestCase):
    def test_canonical_assets_and_exclusions_remain_review_only(self):
        scope = _scope(("fixture.example.test", "127.0.0.1"), ("blocked.example.test",))
        before = (scope.assets, scope.excluded_assets)
        receipt = review_asset_identity_shape(scope)
        self.assertEqual(receipt.decision, "REVIEW_ONLY")
        self.assertEqual((scope.assets, scope.excluded_assets), before)
        self.assertFalse(receipt)
        self.assertEqual(
            set(receipt.as_public_dict()),
            {"decision", "authorization_verified", "consent_verified",
             "grant_permitted", "dispatch_permitted", "merge_permitted",
             "release_permitted"},
        )
        self.assertTrue(all(value is False for key, value in receipt.as_public_dict().items()
                            if key != "decision"))

    def test_empty_blank_spaced_control_and_nontext_allowed_assets_hold(self):
        bad = [(), ("",), (" ",), (" fixture.example.test",),
               ("fixture.example.test ",), ("\n",), (True,), (42,),
               (None,), (object(),), ("fixture\x00.example.test",)]
        for assets in bad:
            with self.subTest(assets=type(assets[0]).__name__ if assets else "empty"):
                self.assertEqual(review_asset_identity_shape(_scope(assets)).decision, "HOLD")

    def test_blank_spaced_control_and_nontext_exclusions_hold(self):
        bad = [("",), (" ",), (" blocked.example.test",),
               ("blocked.example.test ",), ("\x7f",), (False,),
               (0,), (None,), (object(),)]
        for excluded in bad:
            with self.subTest(excluded=type(excluded[0]).__name__):
                self.assertEqual(review_asset_identity_shape(_scope(excluded=excluded)).decision, "HOLD")

    def test_polymorphic_elements_are_denied_before_str_methods(self):
        count = {"strip": 0}
        class DeceptiveText(str):
            def strip(self, *args, **kwargs):
                count["strip"] += 1
                raise AssertionError("untrusted override executed")
        fake = DeceptiveText("fixture.example.test")
        self.assertEqual(review_asset_identity_shape(_scope((fake,))).decision, "HOLD")
        self.assertEqual(review_asset_identity_shape(_scope(excluded=(fake,))).decision, "HOLD")
        self.assertEqual(count["strip"], 0)

    def test_subclassed_scope_is_denied_before_attribute_access(self):
        class HostileScope(ScopeDefinition):
            def __getattribute__(self, name):
                raise AssertionError("scope subclass getter executed")
        hostile = HostileScope(("fixture.example.test",), RiskLevel.PASSIVE)
        self.assertEqual(review_asset_identity_shape(hostile).decision, "HOLD")

    def test_wrong_collection_type_and_bounded_lengths_hold(self):
        for values in [["fixture.example.test"], {"fixture.example.test"},
                       "fixture.example.test", ("x" * 2049,),
                       ("fixture.example.test",) * 257]:
            self.assertEqual(review_asset_identity_shape(_scope(assets=values)).decision, "HOLD")
        self.assertEqual(review_asset_identity_shape(_scope(("x" * 2048,))).decision,
                         "REVIEW_ONLY")
        self.assertEqual(review_asset_identity_shape(_scope(("x",) * 256)).decision,
                         "REVIEW_ONLY")
        self.assertEqual(review_asset_identity_shape(_scope(excluded=["x"])).decision,
                         "HOLD")

    def test_public_receipts_do_not_echo_assets_or_confer_authority(self):
        marker = "private-fixture-marker-never-echo"
        for receipt in (review_asset_identity_shape(_scope((marker,))),
                        review_asset_identity_shape(_scope((marker + " ",)))):
            self.assertIs(type(receipt), AssetIdentityShapeReceipt)
            self.assertFalse(receipt)
            wire = repr(receipt.as_public_dict())
            self.assertNotIn(marker, wire)
            self.assertNotIn("fixture.example.test", wire)
            for flag in ("authorization_verified", "consent_verified", "grant_permitted",
                         "dispatch_permitted", "merge_permitted", "release_permitted"):
                self.assertIs(receipt.as_public_dict()[flag], False)
            with self.assertRaises(Exception):
                receipt.decision = "APPROVED"

    def test_review_never_opens_file_socket_database_or_process(self):
        scope = _scope()
        with patch("builtins.open", side_effect=AssertionError("file")), \
             patch("sqlite3.connect", side_effect=AssertionError("database")), \
             patch("socket.socket", side_effect=AssertionError("socket")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            self.assertEqual(review_asset_identity_shape(scope).decision, "REVIEW_ONLY")


class ExistingDomainSourceRed376(unittest.TestCase):
    """The current DomainStore has NOT integrated this optional reviewer.

    These are intentionally still-open original-source safety violations.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.temp.name) / "fictional.db")
        self.operator = AccessContext("fictional-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Fictional Client 376")
        self.engagement = self.store.create_engagement(
            self.operator, client.client_id, "offline synthetic shape")
        self.start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.end = datetime(2027, 1, 1, tzinfo=timezone.utc)

    def tearDown(self):
        self.temp.cleanup()

    def _record(self, scope):
        return self.store.record_authorization_grant(
            self.operator, self.engagement.engagement_id,
            "fictional-reviewer", "NOT-CONSENT", scope, self.start, self.end)

    def _row_count(self):
        with self.store._connect() as con:
            return con.execute("SELECT COUNT(*) FROM authorization_grants").fetchone()[0]

    @unittest.expectedFailure
    def test_original_source_rejects_blank_allowlisted_identity_before_sqlite(self):
        before = self._row_count()
        with self.assertRaises(ValueError):
            self._record(_scope((" ",)))
        self.assertEqual(self._row_count(), before)

    @unittest.expectedFailure
    def test_original_source_rejects_blank_exclusion_before_sqlite(self):
        before = self._row_count()
        with self.assertRaises(ValueError):
            self._record(_scope(excluded=(" ",)))
        self.assertEqual(self._row_count(), before)

    @unittest.expectedFailure
    def test_original_source_rejects_nontext_exclusion_before_sqlite(self):
        before = self._row_count()
        with self.assertRaises(ValueError):
            self._record(_scope(excluded=(123,)))
        self.assertEqual(self._row_count(), before)

    def test_canonical_legacy_grant_roundtrip_still_works(self):
        grant = self._record(_scope())
        self.assertEqual(grant.scope.assets, ("fixture.example.test",))
        stored = self.store.list_authorization_grants(self.operator,
                                                      self.engagement.engagement_id)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].scope.assets, grant.scope.assets)


class ExactRedOracle376(unittest.TestCase):
    def test_three_real_source_red_cases_are_not_hidden_as_green(self):
        names = ("test_original_source_rejects_blank_allowlisted_identity_before_sqlite",
                 "test_original_source_rejects_blank_exclusion_before_sqlite",
                 "test_original_source_rejects_nontext_exclusion_before_sqlite")
        result = unittest.TestResult()
        suite = unittest.TestSuite(ExistingDomainSourceRed376(name) for name in names)
        suite.run(result)
        self.assertEqual(result.testsRun, 3)
        self.assertFalse(result.errors)
        self.assertFalse(result.failures)
        self.assertEqual(len(result.expectedFailures), 3)
        self.assertFalse(result.unexpectedSuccesses)


if __name__ == "__main__":
    unittest.main()
