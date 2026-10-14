"""Standalone W27 decoder contract against real disposable finding evidence rows.

This tests the optional pure decoder. It deliberately does not patch or
assert that the canonical DomainStore read path has been fixed.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.finding_evidence_json_checked_optin_w27 import (
    decode_finding_evidence_checked,
)
from lightup.models import Severity


class CheckedEvidenceJsonW27Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("synthetic-w27-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "W27 synthetic client")
        engagement = self.store.create_engagement(
            self.operator, client.client_id, "W27 synthetic engagement"
        )
        self.finding = self.store.record_finding(
            self.operator, engagement.engagement_id,
            "W27 synthetic finding", Severity.LOW, "offline.synthetic",
            "synthetic impact", "synthetic remediation",
            evidence_ids=("evidence:one", "evidence:two"),
        )

    def _set_read_raw(self, raw):
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (raw, self.finding.finding_id),
            )
        with self.store._connect() as con:
            row = con.execute(
                "SELECT evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        return row["evidence_ids_json"]

    def _assert_bad(self, raw):
        stored = self._set_read_raw(raw)
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            decode_finding_evidence_checked(stored)
        with self.store._connect() as con:
            post = con.execute(
                "SELECT evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()
        self.assertEqual(stored, post["evidence_ids_json"])

    def test_canonical_refs_preserve_exact_order_and_whitespace(self):
        raw = '["évidence:alpha","evidence:beta ","evidence:gamma"]'
        stored = self._set_read_raw(raw)
        self.assertEqual(
            decode_finding_evidence_checked(stored),
            ("évidence:alpha", "evidence:beta ", "evidence:gamma"),
        )
        self.assertEqual(stored, raw)

    def test_empty_list_is_compatible_with_manual_finding(self):
        stored = self._set_read_raw("[]")
        self.assertEqual(decode_finding_evidence_checked(stored), ())

    def test_invalid_top_level_and_decoder_shapes_converge(self):
        bad = (
            "null", "true", "false", "7", '"evidence:one"',
            '{"evidence:one":true}', '["evidence:one"',
            "NaN", "Infinity", "-Infinity", "1e9999",
        )
        for raw in bad:
            with self.subTest(raw=raw):
                self._assert_bad(raw)

    def test_member_typing_blank_and_duplicate_fail_atomically(self):
        bad = (
            '["evidence:one",null]', '["evidence:one",7]',
            '["evidence:one",true]', '["evidence:one",{}]',
            '["  "]', '["evidence:one","evidence:one"]',
        )
        for raw in bad:
            with self.subTest(raw=raw):
                self._assert_bad(raw)

    def test_bounded_deeply_nested_valid_json_cannot_escape_recursion_error(self):
        self._assert_bad("[" * 2048 + '"evidence"' + "]" * 2048)

    def test_provisional_source_owner_ceilings_are_fail_closed(self):
        self._assert_bad("[" + ",".join(['"evidence"'] * 129) + "]")
        self._assert_bad('["' + "x" * 4097 + '"]')
        self._assert_bad(" " * 262145 + "[]")

    def test_untrusted_non_string_and_surrogate_deny_with_same_error(self):
        class StrSubclass(str):
            pass

        for value in (None, b"[]", [], {}, StrSubclass("[]"), '["\\ud800"]'):
            with self.subTest(value=repr(value)[:25]):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    decode_finding_evidence_checked(value)


if __name__ == "__main__":
    unittest.main()
