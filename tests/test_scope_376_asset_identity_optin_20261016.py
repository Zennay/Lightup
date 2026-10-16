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
    AssetIdentityShapeReceipt, _canonical_asset_snapshot,
    review_asset_identity_shape,
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
               ("fixture.example.test ",), ("fixture.example.test other",), ("fixture.example.test\tother",), ("fixture.example.test\u00a0other",), ("fixture.example.test\u2028other",), ("\n",), (True,), (42,),
               (None,), (object(),), ("fixture\x00.example.test",)]
        for assets in bad:
            with self.subTest(assets=type(assets[0]).__name__ if assets else "empty"):
                self.assertEqual(review_asset_identity_shape(_scope(assets)).decision, "HOLD")

    def test_blank_spaced_control_and_nontext_exclusions_hold(self):
        bad = [("",), (" ",), (" blocked.example.test",),
               ("blocked.example.test ",), ("blocked.example.test other",), ("blocked.example.test\u00a0other",), ("\x7f",), (False,),
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
        self.assertEqual(review_asset_identity_shape(_scope(
            tuple("fixture-%03d.example.test" % index for index in range(256))
        )).decision, "REVIEW_ONLY")
        self.assertEqual(review_asset_identity_shape(_scope(excluded=["x"])).decision,
                         "HOLD")

    def test_missing_dataclass_instance_fields_always_hold(self):
        # Frozen is not tamper-proof. Exclusions must not fall back to ().
        for field in ("assets", "excluded_assets", "allowed_capabilities", "max_risk"):
            with self.subTest(field=field):
                scope = _scope(excluded=("blocked.example.test",))
                object.__delattr__(scope, field)
                self.assertEqual(review_asset_identity_shape(scope).decision, "HOLD")
        bare = object.__new__(ScopeDefinition)
        self.assertEqual(review_asset_identity_shape(bare).decision, "HOLD")

    def test_extra_or_polymorphic_instance_attribute_keys_hold_without_methods(self):
        scope = _scope()
        object.__setattr__(scope, "untrusted_extra", "fictional")
        self.assertEqual(review_asset_identity_shape(scope).decision, "HOLD")

        counts = {"hash": 0, "eq": 0}
        class UntrustedKey:
            def __hash__(self):
                counts["hash"] += 1
                return 987654321
            def __eq__(self, other):
                counts["eq"] += 1
                raise AssertionError("untrusted key comparison")
        key = UntrustedKey()
        scope = _scope(excluded=("blocked.example.test",))
        # Simulate corrupt exact-class __dict__ with 4 keys but not all native.
        fields = object.__getattribute__(scope, "__dict__")
        fields.pop("excluded_assets")
        fields[key] = ("blocked.example.test",)
        before = counts.copy()
        self.assertEqual(review_asset_identity_shape(scope).decision, "HOLD")
        self.assertEqual(counts, before)

    def test_exact_duplicates_and_allow_exclude_collisions_are_hold_only(self):
        cases = (
            _scope(("fixture.example.test", "fixture.example.test")),
            _scope(excluded=("blocked.example.test", "blocked.example.test")),
            _scope(("fixture.example.test",), ("fixture.example.test",)),
            _scope(("fixture.example.test", "other.example.test"),
                   ("other.example.test",)),
        )
        for scope in cases:
            with self.subTest(case=scope):
                receipt = review_asset_identity_shape(scope)
                self.assertEqual(receipt.decision, "HOLD")
                self.assertFalse(receipt)
                self.assertTrue(all(
                    value is False for key, value in receipt.as_public_dict().items()
                    if key != "decision"
                ))

    def test_no_normalization_or_alias_authority_is_inferred(self):
        # Case variants are only raw-text shape-reviewed: their equivalence,
        # ownership and scope permission require independent owner checks.
        scope = _scope(("EXAMPLE.test",), ("example.test",))
        receipt = review_asset_identity_shape(scope)
        self.assertEqual(receipt.decision, "REVIEW_ONLY")
        self.assertFalse(receipt)
        self.assertIs(receipt.as_public_dict()["grant_permitted"], False)

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

    def test_decision_receipts_cannot_be_forged_as_approval(self):
        class ForgedStatus(str):
            def __eq__(self, other):
                raise AssertionError("untrusted status comparator ran")
        for status in ("APPROVED", "PASS", "RELEASED", True, False,
                       None, ForgedStatus("REVIEW_ONLY")):
            with self.subTest(status_type=type(status).__name__):
                with self.assertRaises(ValueError):
                    AssetIdentityShapeReceipt(status)
        for status in ("HOLD", "REVIEW_ONLY"):
            receipt = AssetIdentityShapeReceipt(status)
            self.assertFalse(receipt)
            self.assertEqual(receipt.as_public_dict()["decision"], status)

    def test_frozen_receipts_mutated_by_reflection_still_serialize_hold(self):
        class DangerousStatus(str):
            def __eq__(self, other):
                raise AssertionError("hostile string comparator must not run")
        statuses = ("APPROVED", "RELEASED", "PASS", True, 7, None,
                    DangerousStatus("REVIEW_ONLY"), object())
        for status in statuses:
            with self.subTest(value_type=type(status).__name__):
                receipt = AssetIdentityShapeReceipt("REVIEW_ONLY")
                object.__setattr__(receipt, "decision", status)
                self.assertFalse(receipt)
                actual = receipt.as_public_dict()
                self.assertEqual(actual["decision"], "HOLD")
                self.assertTrue(all(value is False
                                    for key, value in actual.items()
                                    if key != "decision"))
        receipt = AssetIdentityShapeReceipt("REVIEW_ONLY")
        object.__delattr__(receipt, "decision")
        self.assertEqual(receipt.as_public_dict()["decision"], "HOLD")
        self.assertFalse(receipt)

    def test_reflective_scope_mutations_do_not_make_missing_exclusions_reviewable(self):
        scope = _scope(excluded=("excluded.example.test",))
        first = review_asset_identity_shape(scope)
        self.assertEqual(first.decision, "REVIEW_ONLY")
        fields = object.__getattribute__(scope, "__dict__")
        # Direct dict writes defeat frozen dataclass access restrictions.
        fields.pop("excluded_assets")
        self.assertEqual(review_asset_identity_shape(scope).decision, "HOLD")
        fields["excluded_assets"] = ["excluded.example.test"]
        self.assertEqual(review_asset_identity_shape(scope).decision, "HOLD")
        fields["excluded_assets"] = ("excluded.example.test",)
        self.assertEqual(review_asset_identity_shape(scope).decision, "REVIEW_ONLY")

    def test_deterministic_512_noncanonical_identity_variants_hold(self):
        # Only syntactic shape review; not alias, ownership or network checks.
        for i in range(512):
            seed = "fixture-%03d.example.test" % i
            bad = (
                seed + "\u00a0extra" if i % 4 == 0 else
                seed + "\tinvalid" if i % 4 == 1 else
                seed + " another" if i % 4 == 2 else
                seed + "\x00invalid"
            )
            with self.subTest(index=i):
                self.assertEqual(review_asset_identity_shape(_scope((bad,))).decision, "HOLD")
                self.assertEqual(review_asset_identity_shape(
                    _scope(excluded=(bad,))
                ).decision, "HOLD")

    def test_private_snapshot_is_immutable_across_original_scope_mutation(self):
        scope = _scope(("fixture.example.test",),
                       ("excluded.example.test",))
        values = _canonical_asset_snapshot(scope)
        self.assertEqual(values, (("fixture.example.test",),
                                  ("excluded.example.test",)))
        self.assertIs(type(values[0]), tuple)
        self.assertIs(type(values[1]), tuple)
        # Malicious in-process actor bypasses dataclass frozen assignment.
        object.__setattr__(scope, "assets", (" ",))
        object.__setattr__(scope, "excluded_assets", (123,))
        self.assertEqual(values, (("fixture.example.test",),
                                  ("excluded.example.test",)))
        self.assertEqual(review_asset_identity_shape(scope).decision, "HOLD")
        self.assertIsNone(_canonical_asset_snapshot(scope))

    def test_snapshot_never_uses_client_overrides_or_leaks_to_status_receipt(self):
        class HostileScope(ScopeDefinition):
            def __getattribute__(self, name):
                raise AssertionError("hostile scope attribute access")
        hostile = HostileScope(("fixture.example.test",), RiskLevel.PASSIVE)
        self.assertIsNone(_canonical_asset_snapshot(hostile))
        self.assertEqual(review_asset_identity_shape(hostile).decision, "HOLD")
        marker = "sensitive-offline-only"
        scope = _scope((marker,))
        self.assertEqual(_canonical_asset_snapshot(scope)[0], (marker,))
        self.assertNotIn(marker, repr(review_asset_identity_shape(scope).as_public_dict()))

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

    @unittest.expectedFailure
    def test_original_source_rejects_nontext_allowed_asset_before_sqlite(self):
        before = self._row_count()
        with self.assertRaises(ValueError):
            self._record(_scope((123,)))
        self.assertEqual(self._row_count(), before)

    @unittest.expectedFailure
    def test_original_source_rejects_control_char_allowed_asset_before_sqlite(self):
        before = self._row_count()
        with self.assertRaises(ValueError):
            self._record(_scope(("fixture\x00.example.test",)))
        self.assertEqual(self._row_count(), before)

    @unittest.expectedFailure
    def test_original_source_rejects_missing_exclusions_before_sqlite(self):
        scope = _scope(excluded=("excluded.example.test",))
        object.__delattr__(scope, "excluded_assets")
        before = self._row_count()
        with self.assertRaises(ValueError):
            self._record(scope)
        self.assertEqual(self._row_count(), before)

    @unittest.expectedFailure
    def test_original_source_rejects_internal_whitespace_before_sqlite(self):
        before = self._row_count()
        with self.assertRaises(ValueError):
            self._record(_scope(("fixture.example.test with space",)))
        self.assertEqual(self._row_count(), before)

    def test_canonical_legacy_grant_roundtrip_still_works(self):
        grant = self._record(_scope())
        self.assertEqual(grant.scope.assets, ("fixture.example.test",))
        stored = self.store.list_authorization_grants(self.operator,
                                                      self.engagement.engagement_id)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].scope.assets, grant.scope.assets)



class OwnerAdoptionSameConnection376(unittest.TestCase):
    """Opt-in review at the ACTUAL record call; original method remains untouched.

    This is a simulation inside disposable SQLite, not installed enforcement.
    """
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.temp.name) / "isolated-376.db")
        self.operator = AccessContext("operator-fixture", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Isolated Fake Lab")
        self.engagement = self.store.create_engagement(
            self.operator, client.client_id, "synthetic approval only")
        self.start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.end = datetime(2027, 1, 1, tzinfo=timezone.utc)

    def tearDown(self):
        self.temp.cleanup()

    def _record(self, scope):
        return self.store.record_authorization_grant(
            self.operator, self.engagement.engagement_id, "fixture-reviewer",
            "NOT-CONSENT", scope, self.start, self.end)

    def _persisted_snapshot(self):
        with self.store._connect() as con:
            return tuple(tuple(row) for row in con.execute(
                "SELECT grant_id, client_id, engagement_id, approved_by, reference, "
                "assets_json, excluded_assets_json, allowed_capabilities_json, "
                "max_risk, valid_from, valid_until, recurring_retest_allowed, created_at "
                "FROM authorization_grants ORDER BY rowid"
            ))

    @staticmethod
    def _owner_candidate(original):
        def review_before_record(store, ctx, engagement_id, approved_by, reference,
                                 scope, valid_from, valid_until,
                                 recurring_retest_allowed=False):
            result = review_asset_identity_shape(scope)
            # Compare only immutable built-in status; never use truthiness as authority.
            if result.decision != "REVIEW_ONLY":
                raise ValueError("asset identity shape requires independent review")
            return original(store, ctx, engagement_id, approved_by, reference,
                            scope, valid_from, valid_until, recurring_retest_allowed)
        return review_before_record

    def test_all_bad_assets_deny_before_original_record_with_no_sqlite_mutation(self):
        original = DomainStore.record_authorization_grant
        lost_exclusion = _scope(excluded=("blocked.example.test",))
        object.__delattr__(lost_exclusion, "excluded_assets")
        rejected = (
            lost_exclusion,
            _scope((" ",)),
            _scope(("fixture.example.test", "")),
            _scope(("fixture.example.test ",)),
            _scope(("fixture.example.test other",)),
            _scope((123,)),
            _scope(excluded=(" ",)),
            _scope(excluded=(False,)),
            _scope(excluded=("fixture.example.test\n",)),
            _scope(excluded=("fixture.example.test\u00a0other",)),
            _scope(excluded=("fixture.example.test", None)),
            _scope(excluded=("secret.invalid",) * 257),
            _scope(("fixture.example.test", "fixture.example.test")),
            _scope(excluded=("blocked.example.test", "blocked.example.test")),
            _scope(("fixture.example.test",), ("fixture.example.test",)),
        )
        with patch.object(DomainStore, "record_authorization_grant",
                          self._owner_candidate(original)):
            for scope in rejected:
                with self.subTest(allow=repr(scope.assets)[:40],
                                  exclude=repr(scope.excluded_assets)[:40]):
                    before = self._persisted_snapshot()
                    with self.assertRaisesRegex(
                        ValueError, "^asset identity shape requires independent review$"
                    ) as error:
                        self._record(scope)
                    self.assertNotIn("secret.invalid", str(error.exception))
                    self.assertEqual(self._persisted_snapshot(), before)
        self.assertIs(DomainStore.record_authorization_grant, original)

    def test_bad_identity_is_rejected_before_original_grant_or_any_db_access(self):
        # Strict call-boundary proof, not a production middleware installation.
        called = []
        def forbidden_original(*args, **kwargs):
            called.append(True)
            raise AssertionError("original grant record reached")
        bad_cases = (
            _scope(("private-marker\x00.example.test",)),
            _scope((42,)),
            _scope(excluded=("private-marker\u00a0excluded",)),
            _scope(excluded=("excluded.example.test", "excluded.example.test")),
        )
        with patch.object(DomainStore, "record_authorization_grant",
                          self._owner_candidate(forbidden_original)), \
             patch.object(DomainStore, "_connect",
                          side_effect=AssertionError("SQLite opened")), \
             patch.object(DomainStore, "get_engagement",
                          side_effect=AssertionError("engagement looked up")):
            for scope in bad_cases:
                with self.subTest(index=repr(scope.assets)[:32]):
                    with self.assertRaisesRegex(
                        ValueError, "^asset identity shape requires independent review$"
                    ) as caught:
                        self._record(scope)
                    self.assertNotIn("private-marker", str(caught.exception))
        self.assertFalse(called)

    def test_shape_only_success_never_short_circuits_original_grant_gate(self):
        # A positive review can only reach the separate, original owner method.
        calls = []
        def owner_gate(*args, **kwargs):
            calls.append(args)
            raise PermissionError("fictional owner gate still required")
        original = DomainStore.record_authorization_grant
        with patch.object(DomainStore, "record_authorization_grant",
                          self._owner_candidate(owner_gate)):
            with self.assertRaisesRegex(PermissionError, "fictional owner gate still required"):
                self._record(_scope())
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][0], self.store)
        self.assertIs(DomainStore.record_authorization_grant, original)
        self.assertEqual(self._persisted_snapshot(), ())

    def test_snapshot_value_contract_can_preserve_exclusions_after_input_mutation(self):
        # Owner handoff only: a fresh fictional scope made from the snapshot
        # is stable even when the original dataclass is modified afterward.
        original = _scope(("fixture.example.test",), ("blocked.example.test",))
        values = _canonical_asset_snapshot(original)
        self.assertIsNotNone(values)
        object.__setattr__(original, "assets", (" ",))
        object.__setattr__(original, "excluded_assets", (123,))
        frozen_fixture = _scope(assets=values[0], excluded=values[1])
        before = self._persisted_snapshot()
        self.assertEqual(before, ())
        with patch.object(DomainStore, "record_authorization_grant",
                          self._owner_candidate(DomainStore.record_authorization_grant)):
            recorded = self._record(frozen_fixture)
        self.assertEqual(recorded.scope.assets, ("fixture.example.test",))
        self.assertEqual(recorded.scope.excluded_assets, ("blocked.example.test",))
        self.assertEqual(len(self._persisted_snapshot()), 1)
        self.assertEqual(review_asset_identity_shape(original).decision, "HOLD")

    def test_ordinary_grant_passes_only_through_temporary_review_wrapper(self):
        original = DomainStore.record_authorization_grant
        scope = _scope(("fixture.example.test",), ("blocked.example.test",))
        with patch.object(DomainStore, "record_authorization_grant",
                          self._owner_candidate(original)):
            recorded = self._record(scope)
            persisted = self._persisted_snapshot()
            self.assertEqual(len(persisted), 1)
            self.assertEqual(recorded.scope, scope)
            self.assertEqual(
                self.store.list_authorization_grants(
                    self.operator, self.engagement.engagement_id
                )[0].scope, scope
            )
        self.assertIs(DomainStore.record_authorization_grant, original)
        self.assertEqual(self._persisted_snapshot(), persisted)

    def test_original_source_unmodified_and_bad_exclusion_still_persists(self):
        original = DomainStore.record_authorization_grant
        bad_scope = _scope(excluded=(" ",))
        before = self._persisted_snapshot()
        with patch.object(DomainStore, "record_authorization_grant",
                          self._owner_candidate(original)):
            with self.assertRaises(ValueError):
                self._record(bad_scope)
            self.assertEqual(self._persisted_snapshot(), before)
        self.assertIs(DomainStore.record_authorization_grant, original)
        # This demonstrates the still-open original-source defect, NOT an allow decision.
        legacy = self._record(bad_scope)
        self.assertEqual(legacy.scope.excluded_assets, (" ",))
        self.assertEqual(len(self._persisted_snapshot()), 1)

    def test_review_does_not_suppress_original_role_isolation(self):
        original = DomainStore.record_authorization_grant
        client_context = AccessContext("fake-client", Role.CLIENT_ADMIN,
                                       self.engagement.client_id)
        with patch.object(DomainStore, "record_authorization_grant",
                          self._owner_candidate(original)):
            before = self._persisted_snapshot()
            with self.assertRaises(Exception):
                self.store.record_authorization_grant(
                    client_context, self.engagement.engagement_id, "fixture-reviewer",
                    "NOT-CONSENT", _scope(), self.start, self.end)
            self.assertEqual(self._persisted_snapshot(), before)
        self.assertIs(DomainStore.record_authorization_grant, original)


class ExactRedOracle376(unittest.TestCase):
    def test_seven_real_source_red_cases_are_not_hidden_as_green(self):
        names = ("test_original_source_rejects_blank_allowlisted_identity_before_sqlite",
                 "test_original_source_rejects_blank_exclusion_before_sqlite",
                 "test_original_source_rejects_nontext_exclusion_before_sqlite",
                 "test_original_source_rejects_nontext_allowed_asset_before_sqlite",
                 "test_original_source_rejects_control_char_allowed_asset_before_sqlite",
                 "test_original_source_rejects_missing_exclusions_before_sqlite",
                 "test_original_source_rejects_internal_whitespace_before_sqlite")
        result = unittest.TestResult()
        suite = unittest.TestSuite(ExistingDomainSourceRed376(name) for name in names)
        suite.run(result)
        self.assertEqual(result.testsRun, 7)
        self.assertFalse(result.errors)
        self.assertFalse(result.failures)
        self.assertEqual(len(result.expectedFailures), 7)
        self.assertFalse(result.unexpectedSuccesses)


if __name__ == "__main__":
    unittest.main()
