"""Integration proof for opt-in, read-only DomainStore advisory adapter."""
from __future__ import annotations

import tempfile
import sqlite3
from contextlib import contextmanager
from pathlib import Path
import unittest
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.models import RetestStatus, Severity
from lightup.remediation_review_source import read_remediation_review_queue


class RemediationReviewSourceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = DomainStore(Path(tmp.name) / "synthetic.sqlite")
        self.operator = AccessContext("op-review-reader", Role.OPERATOR)
        self.first = self.store.create_client(self.operator, "Synthetic client first")
        self.second = self.store.create_client(self.operator, "Synthetic client second")
        self.eng_first = self.store.create_engagement(
            self.operator, self.first.client_id, "Synthetic engagement first"
        )
        self.eng_second = self.store.create_engagement(
            self.operator, self.second.client_id, "Synthetic engagement second"
        )
        self.row_first = self.store.record_finding(
            self.operator, self.eng_first.engagement_id,
            title="Confidential first finding", severity=Severity.MEDIUM,
            asset="lab://first", impact="private first",
            remediation="Secure the synthetic fixture",
            evidence_ids=("synthetic-ref-first",),
        )
        self.row_second = self.store.record_finding(
            self.operator, self.eng_second.engagement_id,
            title="Confidential second finding", severity=Severity.HIGH,
            asset="lab://second", impact="private second",
            remediation="Secure second synthetic fixture",
            evidence_ids=("synthetic-ref-second",),
        )
        self.client_ctx = AccessContext(
            "synthetic-client-member", Role.CLIENT_MEMBER, self.first.client_id
        )

    def _read(self, ctx=None, engagement_id=None):
        return read_remediation_review_queue(
            self.store, ctx or self.client_ctx,
            engagement_id=engagement_id or self.eng_first.engagement_id,
        )

    def _raw(self):
        with self.store._connect() as con:
            row = con.execute(
                "SELECT client_id, engagement_id, evidence_ids_json, retest_status "
                "FROM findings WHERE finding_id=?", (self.row_first.finding_id,)
            ).fetchone()
            return tuple(row)

    def _corrupt(self, column, value):
        assert column in {"evidence_ids_json", "client_id"}
        with self.store._connect() as con:
            con.execute(
                f"UPDATE findings SET {column}=? WHERE finding_id=?",
                (value, self.row_first.finding_id),
            )

    def test_client_session_context_reads_only_its_own_engagement(self):
        result = self._read()
        self.assertEqual(len(result.items), 1)
        self.assertEqual(result.items[0].referenced_evidence_count, 1)
        self.assertFalse(result.remediation_authorized)
        self.assertFalse(result.evidence_verified)
        for private in (
            self.first.client_id, self.eng_first.engagement_id,
            self.row_first.title, self.row_first.asset,
            "synthetic-ref-first", "synthetic-ref-second",
        ):
            self.assertNotIn(private, result.to_json())

    def test_operator_must_still_choose_a_single_engagement(self):
        first = self._read(ctx=self.operator)
        second = self._read(
            ctx=self.operator, engagement_id=self.eng_second.engagement_id
        )
        self.assertEqual(len(first.items), 1)
        self.assertEqual(len(second.items), 1)
        self.assertNotEqual(first.digest_sha256, second.digest_sha256)

    def test_cross_tenant_read_preserves_domain_access_denial(self):
        with self.assertRaises(TenantIsolationError) as caught:
            self._read(engagement_id=self.eng_second.engagement_id)
        self.assertEqual(str(caught.exception), "remediation review tenant scope denied")
        self.assertNotIn(self.second.client_id, str(caught.exception))
        self.assertNotIn(self.eng_second.engagement_id, str(caught.exception))

    def test_unknown_engagement_selector_has_no_secret_in_error(self):
        secret = "nonexistent-private-engagement-id"
        before = self._raw()
        with self.assertRaises(ValueError) as caught:
            self._read(ctx=self.operator, engagement_id=secret)
        self.assertEqual(
            str(caught.exception), "remediation review engagement not found"
        )
        self.assertNotIn(secret, str(caught.exception))
        self.assertEqual(self._raw(), before)

    def test_missing_engagement_cannot_trigger_global_operator_findings_read(self):
        for invalid in ("", "  ", [], 1, None, b"valid",
                        "bad\nselector", "e" * 129):
            with self.subTest(invalid=repr(invalid)[:30]):
                with self.assertRaises(ValueError):
                    read_remediation_review_queue(
                        self.store, self.operator, engagement_id=invalid
                    )

    def test_malformed_persisted_json_rejected_with_generic_error_and_zero_write(self):
        for raw in ('["partial"', "null", "123", '{"bad":true}'):
            with self.subTest(raw=raw):
                self._corrupt("evidence_ids_json", raw)
                before = self._raw()
                with self.assertRaises(ValueError) as caught:
                    self._read()
                self.assertEqual(
                    str(caught.exception), "remediation evidence read integrity invalid"
                )
                self.assertEqual(self._raw(), before)

    def test_corrupt_cross_tenant_finding_owner_row_fails_closed_without_write(self):
        self._corrupt("client_id", self.second.client_id)
        before = self._raw()
        with self.assertRaisesRegex(
            ValueError, "^remediation evidence read integrity invalid$"
        ):
            self._read()
        self.assertEqual(self._raw(), before)

    def test_repeated_selection_is_read_only_and_deterministic(self):
        before = self._raw()
        first = self._read()
        second = self._read()
        self.assertEqual(first, second)
        self.assertEqual(self._raw(), before)

    def test_retest_claim_never_authorizes_verified_remediation(self):
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET retest_status=? WHERE finding_id=?",
                (RetestStatus.FIXED.value, self.row_first.finding_id),
            )
        before = self._raw()
        review = self._read()
        self.assertEqual(review.items[0].next_review_step, "independent_retest")
        self.assertFalse(review.items[0].fix_verified)
        self.assertFalse(review.retest_authorized)
        self.assertEqual(self._raw(), before)

    def test_rejects_wrong_context_or_store_class_without_effect(self):
        before = self._raw()
        for store, ctx in ((object(), self.client_ctx),
                           (self.store, object()),
                           (self.store, None)):
            with self.subTest(store=type(store).__name__, ctx=type(ctx).__name__):
                with self.assertRaisesRegex(ValueError, "invalid remediation review read context"):
                    read_remediation_review_queue(
                        store, ctx, engagement_id=self.eng_first.engagement_id,
                    )
        self.assertEqual(self._raw(), before)


    def test_read_adapter_does_not_call_legacy_second_pass_list_findings(self):
        with patch.object(self.store, "list_findings", side_effect=AssertionError(
            "legacy second snapshot must not be read"
        )):
            result = self._read()
        self.assertEqual(len(result.items), 1)

    def test_scope_and_findings_use_one_snapshot_despite_concurrent_reassignment(self):
        original_admission = AccessContext.resolve_client
        state = {"admissions": 0}

        def reassign_after_snapshot(self_ctx, client_id, action):
            state["admissions"] += 1
            if state["admissions"] == 1:
                # A genuine second WAL connection commits a reassignment
                # *after* the first read pins the original authorized scope.
                with self.store._connect() as writer:
                    writer.execute(
                        "UPDATE engagements SET client_id=? WHERE engagement_id=?",
                        (self.second.client_id, self.eng_first.engagement_id),
                    )
            return original_admission(self_ctx, client_id, action)

        before = self._raw()
        with patch.object(AccessContext, "resolve_client",
                          new=reassign_after_snapshot):
            historical = self._read()

        self.assertEqual(state["admissions"], 1)
        self.assertEqual(len(historical.items), 1)
        self.assertEqual(before, self._raw())
        self.assertFalse(historical.authorization_verified)
        # The next transaction sees a reassignment and refuses client A.
        with self.assertRaises(TenantIsolationError) as caught:
            self._read()
        self.assertEqual(str(caught.exception), "remediation review tenant scope denied")
        self.assertNotIn(self.second.client_id, str(caught.exception))

    def test_adapter_never_uses_separate_get_engagement_authorization_read(self):
        with patch.object(self.store, "get_engagement",
                          side_effect=AssertionError("second database connection")):
            result = self._read()
        self.assertEqual(len(result.items), 1)
        self.assertFalse(result.retest_authorized)

    def test_tenant_reassignment_before_snapshot_denies_without_row_read(self):
        with self.store._connect() as writer:
            writer.execute(
                "UPDATE engagements SET client_id=? WHERE engagement_id=?",
                (self.second.client_id, self.eng_first.engagement_id),
            )
        before = self._raw()
        with patch.object(DomainStore, "_finding_from_row",
                          side_effect=AssertionError("finding should not decode")):
            with self.assertRaisesRegex(TenantIsolationError, "scope denied"):
                self._read()
        self.assertEqual(before, self._raw())

    def test_reader_pins_snapshot_when_concurrent_writer_changes_evidence(self):
        # WAL mode permits the external writer to commit while this adapter
        # holds its own read transaction. The advisory must refer to the OLD
        # coherent snapshot, never mix old FindingRecord + new raw JSON.
        original = DomainStore._finding_from_row
        replacement = '["synthetic-ref-updated"]'
        callback_count = 0

        def concurrent_write(row):
            nonlocal callback_count
            callback_count += 1
            if callback_count == 1:
                with self.store._connect() as writer:
                    writer.execute(
                        "UPDATE findings SET evidence_ids_json=?, remediation=? "
                        "WHERE finding_id=?",
                        (replacement, "Updated synthetic remediation",
                         self.row_first.finding_id),
                    )
            return original(row)

        with patch.object(DomainStore, "_finding_from_row", side_effect=concurrent_write):
            before = self._read()

        self.assertEqual(callback_count, 1)
        after = self._read()
        self.assertNotEqual(before.digest_sha256, after.digest_sha256)
        self.assertEqual(before.items, after.items)
        self.assertEqual(
            self.store.list_findings(
                self.operator, engagement_id=self.eng_first.engagement_id,
            )[0].evidence_ids,
            ("synthetic-ref-updated",),
        )

    def test_any_bad_record_denies_entire_engagement_without_repair(self):
        second = self.store.record_finding(
            self.operator, self.eng_first.engagement_id,
            title="Second local synthetic row", severity=Severity.LOW,
            asset="lab://first/other", impact="second impact",
            remediation="second synthetic fix",
            evidence_ids=("local-second",),
        )
        with self.store._connect() as writer:
            writer.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                ('{"looks-valid":"key"}', second.finding_id),
            )
        with self.store._connect() as con:
            snapshots = [
                tuple(row) for row in con.execute(
                    "SELECT finding_id, evidence_ids_json FROM findings "
                    "WHERE engagement_id=? ORDER BY finding_id",
                    (self.eng_first.engagement_id,),
                ).fetchall()
            ]
        with self.assertRaisesRegex(
            ValueError, "^remediation evidence read integrity invalid$"
        ):
            self._read()
        with self.store._connect() as con:
            actual = [
                tuple(row) for row in con.execute(
                    "SELECT finding_id, evidence_ids_json FROM findings "
                    "WHERE engagement_id=? ORDER BY finding_id",
                    (self.eng_first.engagement_id,),
                ).fetchall()
            ]
        self.assertEqual(actual, snapshots)

    def test_maximum_128_findings_allows_review_and_129_fails_closed(self):
        with self.store._connect() as connection:
            for index in range(127):
                connection.execute(
                    "INSERT INTO findings "
                    "(finding_id,client_id,engagement_id,title,severity,asset,"
                    "impact,remediation,retest_status,evidence_ids_json,created_at) "
                    "SELECT ?,client_id,engagement_id,title,severity,asset,"
                    "impact,remediation,retest_status,evidence_ids_json,created_at "
                    "FROM findings WHERE finding_id=?",
                    (f"extra-{index:03d}", self.row_first.finding_id),
                )
        review = self._read()
        self.assertEqual(len(review.items), 128)
        with self.store._connect() as connection:
            connection.execute(
                "INSERT INTO findings "
                "(finding_id,client_id,engagement_id,title,severity,asset,"
                "impact,remediation,retest_status,evidence_ids_json,created_at) "
                "SELECT ?,client_id,engagement_id,title,severity,asset,"
                "impact,remediation,retest_status,evidence_ids_json,created_at "
                "FROM findings WHERE finding_id=?",
                ("extra-128", self.row_first.finding_id),
            )
        with self.assertRaisesRegex(
            ValueError, "^remediation evidence read integrity invalid$"
        ):
            self._read()
        with self.store._connect() as con:
            count = con.execute(
                "SELECT count(*) FROM findings WHERE engagement_id=?",
                (self.eng_first.engagement_id,),
            ).fetchone()[0]
        self.assertEqual(count, 129)

    def test_large_persisted_impact_is_truncated_before_row_decoding(self):
        # SELECT * previously materialized the entire attacker-controlled
        # TEXT column before Python could enforce MAX_TEXT. A bounded SQLite
        # projection must hand at most MAX_TEXT+1 characters to the decoder.
        enormous = "oversized-test-value-" * 15000
        with self.store._connect() as writer:
            writer.execute(
                "UPDATE findings SET impact=? WHERE finding_id=?",
                (enormous, self.row_first.finding_id),
            )
        original = DomainStore._finding_from_row
        observed_lengths = []

        def inspect_decode(row):
            observed_lengths.append(len(row["impact"]))
            return original(row)

        with patch.object(DomainStore, "_finding_from_row",
                          side_effect=inspect_decode):
            with self.assertRaisesRegex(ValueError,
                                        "^remediation evidence read integrity invalid$"):
                self._read()
        self.assertEqual(observed_lengths, [8193])
        with self.store._connect() as connection:
            actual_size = connection.execute(
                "SELECT length(impact) FROM findings WHERE finding_id=?",
                (self.row_first.finding_id,),
            ).fetchone()[0]
        self.assertEqual(actual_size, len(enormous))

    def test_oversize_evidence_json_rejected_before_source_decoder(self):
        huge = '["' + ("x" * 300000) + '"]'
        self._corrupt("evidence_ids_json", huge)
        original = self._raw()
        with patch.object(DomainStore, "_finding_from_row",
                          side_effect=AssertionError("never decode huge raw")):
            with self.assertRaisesRegex(ValueError,
                                        "^remediation evidence read integrity invalid$"):
                self._read()
        self.assertEqual(self._raw(), original)

    def test_deeply_nested_json_is_denied_without_recursion_leak_or_writes(self):
        # Python's decoder raises RecursionError for deeply nested JSON,
        # even when the entire source fits our explicit JSON char budget.
        raw = "[" * 1400 + '"synthetic-ref"' + "]" * 1400
        self._corrupt("evidence_ids_json", raw)
        before = self._raw()
        with self.assertRaises(ValueError) as caught:
            self._read()
        self.assertEqual(
            str(caught.exception), "remediation evidence read integrity invalid"
        )
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(self._raw(), before)

    def test_invalid_evidence_envelope_rejected_without_decoder_call(self):
        for raw in ('{"key":"synthetic-ref"}', 'true', '"ref"', "null"):
            with self.subTest(kind=raw[:6]):
                self._corrupt("evidence_ids_json", raw)
                before = self._raw()
                with patch("lightup.remediation_review_source.json.loads",
                           side_effect=AssertionError("invalid envelope reached JSON parser")):
                    with self.assertRaisesRegex(
                        ValueError, "^remediation evidence read integrity invalid$"
                    ):
                        self._read()
                self.assertEqual(self._raw(), before)

    def test_corrupt_sqlite_storage_failure_does_not_leak_internal_details(self):
        # Synthetic error from a malformed storage layer: public advisory
        # errors must not reveal schema/path details or the underlying query.
        with patch.object(self.store, "_connect",
                          side_effect=sqlite3.OperationalError(
                              "private-path-secret: malformed table"
                          )):
            with self.assertRaises(ValueError) as caught:
                self._read()
        self.assertEqual(
            str(caught.exception), "remediation evidence read integrity invalid"
        )
        self.assertNotIn("private-path-secret", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_bounded_projection_preserves_valid_8192_character_source(self):
        long_text = "修" * 8192
        with self.store._connect() as writer:
            writer.execute(
                "UPDATE findings SET remediation=? WHERE finding_id=?",
                (long_text, self.row_first.finding_id),
            )
        review = self._read()
        self.assertEqual(len(review.items), 1)
        self.assertEqual(review.items[0].next_review_step, "review_remediation")
        self.assertNotIn("修", review.to_json())
        self.assertFalse(review.remediation_authorized)

    def test_rejects_noncanonical_json_member_types_without_rewriting(self):
        for raw in ('[null]', '["evidence", 12]', '["one","one"]',
                    '"single-reference"', 'true', '[{}]', '[" "]'):
            with self.subTest(raw=raw):
                self._corrupt("evidence_ids_json", raw)
                before = self._raw()
                with self.assertRaisesRegex(
                    ValueError, "^remediation evidence read integrity invalid$"
                ):
                    self._read()
                self.assertEqual(self._raw(), before)


    def test_client_unknown_and_cross_tenant_engagements_are_indistinguishable(self):
        before = self._raw()
        client_admin = AccessContext(
            "authorized-admin", Role.CLIENT_ADMIN, self.first.client_id,
        )
        for context in (self.client_ctx, client_admin):
            messages = []
            for selector in (
                self.eng_second.engagement_id,
                "nonexistent-opaque-engagement-identifier",
            ):
                with self.subTest(role=context.role, selector=selector):
                    with self.assertRaises(TenantIsolationError) as caught:
                        read_remediation_review_queue(
                            self.store, context, engagement_id=selector,
                        )
                    messages.append(str(caught.exception))
                    self.assertNotIn(selector, messages[-1])
            self.assertEqual(
                messages,
                ["remediation review tenant scope denied"] * 2,
            )
        self.assertEqual(self._raw(), before)

    def test_noncanonical_access_context_roles_subjects_and_tenants_are_denied(self):
        class StrChild(str):
            pass

        bad_contexts = (
            AccessContext("client-user", "client_member", self.first.client_id),
            AccessContext("", Role.OPERATOR),
            AccessContext("  ", Role.OPERATOR),
            AccessContext("unauthenticated" * 20, Role.OPERATOR),
            AccessContext("bad" + chr(10) + "user", Role.OPERATOR),
            AccessContext("client-user", Role.CLIENT_MEMBER,
                          StrChild(self.first.client_id)),
            AccessContext("client-user", Role.CLIENT_MEMBER,
                          self.first.client_id + " "),
        )
        before = self._raw()
        for ctx in bad_contexts:
            with self.subTest(role=repr(ctx.role), subject=repr(ctx.user_id)[:24]):
                with self.assertRaisesRegex(
                    ValueError, "^invalid remediation review read context$"
                ) as caught:
                    read_remediation_review_queue(
                        self.store, ctx, engagement_id=self.eng_first.engagement_id
                    )
                self.assertNotIn(self.first.client_id, str(caught.exception))
        self.assertEqual(self._raw(), before)

    def test_canonical_operator_and_client_admin_still_get_advisory_only(self):
        admin = AccessContext(
            "authorized-synthetic-admin", Role.CLIENT_ADMIN, self.first.client_id
        )
        for ctx in (self.operator, admin, self.client_ctx):
            with self.subTest(role=ctx.role):
                review = read_remediation_review_queue(
                    self.store, ctx, engagement_id=self.eng_first.engagement_id
                )
                self.assertEqual(len(review.items), 1)
                self.assertFalse(review.authorization_verified)
                self.assertFalse(review.retest_authorized)
                self.assertFalse(review.release_authorized)

    def test_sqlite_query_only_pragma_blocks_accidental_advisory_writes(self):
        original_connect = self.store._connect
        decoder = DomainStore._finding_from_row
        seen = []

        @contextmanager
        def intercept_connection():
            with original_connect() as connection:
                seen.append(connection)
                yield connection

        def observe_readonly(row):
            connection = seen[-1]
            self.assertEqual(
                connection.execute("PRAGMA query_only").fetchone()[0], 1
            )
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute(
                    "UPDATE findings SET remediation=? WHERE finding_id=?",
                    ("SHOULD-NOT-PERSIST", self.row_first.finding_id),
                )
            return decoder(row)

        before = self._raw()
        with patch.object(self.store, "_connect", new=intercept_connection):
            with patch.object(DomainStore, "_finding_from_row",
                              side_effect=observe_readonly):
                result = self._read()
        self.assertEqual(len(result.items), 1)
        self.assertEqual(len(seen), 1)
        self.assertEqual(self._raw(), before)


if __name__ == "__main__":
    unittest.main()
