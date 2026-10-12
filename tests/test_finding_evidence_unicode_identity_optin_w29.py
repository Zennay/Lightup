"""W29 optional Unicode evidence-ID admission; synthetic disposable SQLite only.

Tests the *uninstalled* reference helper, not the canonical DomainStore read.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.finding_evidence_json_checked_optin_w27 import (
    decode_finding_evidence_checked,
)
from lightup.finding_evidence_unicode_identity_optin_w29 import (
    decode_finding_evidence_unicode_identity_checked,
)
from lightup.models import Severity


class EvidenceUnicodeIdentityW29Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "evidence.db")
        operator = AccessContext("synthetic-w29-op", Role.OPERATOR)
        client = self.store.create_client(operator, "W29 fictional client")
        engagement = self.store.create_engagement(
            operator, client.client_id, "W29 fictional engagement"
        )
        self.finding = self.store.record_finding(
            operator, engagement.engagement_id, "W29 finding",
            Severity.LOW, "offline.synthetic", "no real impact",
            "local-only remediation", evidence_ids=("ref:one",),
        )

    def _stored(self, refs):
        payload = json.dumps(refs, ensure_ascii=True)
        with self.store._connect() as conn:
            conn.execute(
                "UPDATE findings SET evidence_ids_json=? WHERE finding_id=?",
                (payload, self.finding.finding_id),
            )
        with self.store._connect() as conn:
            return conn.execute(
                "SELECT evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()["evidence_ids_json"]

    def _unchanged(self, original):
        with self.store._connect() as conn:
            after = conn.execute(
                "SELECT evidence_ids_json FROM findings WHERE finding_id=?",
                (self.finding.finding_id,),
            ).fetchone()["evidence_ids_json"]
        self.assertEqual(after, original)

    def _reject_extra_unicode(self, refs):
        stored = self._stored(refs)
        # Establish that W29 checks a real additional invariant over W27.
        self.assertEqual(decode_finding_evidence_checked(stored), tuple(refs))
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            decode_finding_evidence_unicode_identity_checked(stored)
        self._unchanged(stored)

    def test_valid_multilingual_unicode_and_order_preserved(self):
        refs = ["référence:é", "例:二", "ref:emoji-✈\ufe0f", "ref:e\u0301"]
        stored = self._stored(refs)
        self.assertEqual(
            decode_finding_evidence_unicode_identity_checked(stored), tuple(refs)
        )
        self._unchanged(stored)

    def test_valid_empty_manual_evidence_and_plain_space(self):
        for refs in ([], ["evidence:one", "ref:two words"]):
            with self.subTest(refs=refs):
                stored = self._stored(refs)
                self.assertEqual(
                    decode_finding_evidence_unicode_identity_checked(stored),
                    tuple(refs),
                )
                self._unchanged(stored)

    def test_unicode_format_controls_and_bidi_fail_closed(self):
        for char in ("\u200b", "\u200d", "\u202e", "\u2066", "\ufeff"):
            with self.subTest(codepoint=hex(ord(char))):
                self._reject_extra_unicode(["ref:good", "ref:" + char + "bad"])

    def test_ascii_controls_and_surrogates_are_denied(self):
        for char in ("\u0000", "\u000a", "\u007f"):
            with self.subTest(codepoint=hex(ord(char))):
                self._reject_extra_unicode(["ref:one", "ref:" + char])

    def test_escaped_lone_surrogate_is_already_denied_by_w27(self):
        stored = self._stored(["ref:\ud800"])
        for decoder in (
            decode_finding_evidence_checked,
            decode_finding_evidence_unicode_identity_checked,
        ):
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                decoder(stored)
        self._unchanged(stored)

    def test_non_ascii_separators_are_not_ambiguous_ids(self):
        for char in ("\u00a0", "\u2028", "\u2029", "\u3000"):
            with self.subTest(codepoint=hex(ord(char))):
                self._reject_extra_unicode(["ref:one", "ref:" + char + "two"])

    def test_leading_marks_without_a_visible_base_are_denied(self):
        for value in ("\u0301ref:x", " \ufe0fref:y", "\u20ddref:z"):
            with self.subTest(ref=repr(value)):
                self._reject_extra_unicode(["ref:good", value])

    def test_nfkc_identity_collision_is_denied_without_rewriting(self):
        for refs in (["ref:K", "ref:\u212a"], ["ref:A", "ref:\uff21"]):
            with self.subTest(refs=refs):
                self._reject_extra_unicode(refs)

    def test_late_row_ref_is_atomic_and_keeps_original_sqlite(self):
        refs = ["ref:good", "ref:also-good", "ref:\u202eunsafe"]
        self._reject_extra_unicode(refs)

    def test_shape_decoder_errors_remain_generic(self):
        for raw in (None, b"[]", "{}", '["ref:a",null]', '["ref:x","ref:x"]'):
            with self.subTest(value=repr(raw)):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    decode_finding_evidence_unicode_identity_checked(raw)


if __name__ == "__main__":
    unittest.main()
