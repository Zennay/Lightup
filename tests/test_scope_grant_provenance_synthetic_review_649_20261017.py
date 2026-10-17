"""No-authority, no-network, synthetic-only acceptance for scope #649 reviewer."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_scope_grant_provenance_synthetic_649.py"
sys.path.insert(0, str(SCRIPT.parent))

import review_scope_grant_provenance_synthetic_649 as subject


def packet(items=None):
    if items is None:
        items = [{"approved_by": "Synthetic Operator", "reference": "SYNTH-649"}]
    return {
        "schema": subject.SCHEMA,
        "synthetic_only": True,
        "items": items,
    }


def encode(obj):
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")


class _TrapDict(dict):
    def __iter__(self):
        raise AssertionError("foreign mapping executed")


class _TrapStr(str):
    def strip(self, *a, **kw):
        raise AssertionError("foreign text executed")


class Scope649ReviewerTests(unittest.TestCase):
    def test_canonical_synthetic_only_preview_has_no_authority(self):
        receipt = subject.review_batch(packet())
        self.assertIs(receipt.status, subject.ReviewStatus.REVIEW_ONLY)
        self.assertFalse(receipt)
        self.assertFalse(receipt.status)
        self.assertEqual(
            [
                receipt.authorization_verified,
                receipt.consent_verified,
                receipt.permit_issued,
                receipt.dispatch_allowed,
                receipt.execution_enabled,
                receipt.merge_approved,
                receipt.release_approved,
            ], [False] * 7
        )

    def test_refuses_foreign_mapping_without_touching_foreign_iteration(self):
        self.assertIs(subject.review_batch(_TrapDict(packet())).status, subject.ReviewStatus.HOLD)

    def test_refuses_foreign_string_without_stripping(self):
        raw = packet()
        raw["items"][0]["reference"] = _TrapStr("CANONICAL")
        self.assertIs(subject.review_batch(raw).status, subject.ReviewStatus.HOLD)

    def test_both_name_and_reference_are_required(self):
        for key in ("approved_by", "reference"):
            with self.subTest(key=key):
                raw = packet()
                del raw["items"][0][key]
                self.assertIs(subject.review_batch(raw).status, subject.ReviewStatus.HOLD)

    def test_rejects_non_string_provenance_and_polymorphism(self):
        for invalid in (None, False, True, 0, 1.0, (), [], {}, b"abc", _TrapStr("SYNTH")):
            for field in ("approved_by", "reference"):
                with self.subTest(field=field, invalid=type(invalid).__name__):
                    raw = packet()
                    raw["items"][0][field] = invalid
                    self.assertIs(subject.review_batch(raw).status, subject.ReviewStatus.HOLD)

    def test_rejects_whitespace_blank_edges_controls_and_noncanonical_unicode(self):
        bad = ("", " ", "  x", "x  ", "\tX", "X\n", "X\x00Y",
               "a\u202eb", "a\u200db", "e\u0301", "X\u2028Y", "x" * 129)
        for value in bad:
            for field in ("approved_by", "reference"):
                with self.subTest(field=field, value=repr(value)):
                    raw = packet()
                    raw["items"][0][field] = value
                    self.assertIs(subject.review_batch(raw).status, subject.ReviewStatus.HOLD)

    def test_allows_canonical_unicode_for_fictional_labels(self):
        value = packet([{"approved_by": "Élodie", "reference": "SYNTH-É"}])
        self.assertIs(subject.review_batch(value).status, subject.ReviewStatus.REVIEW_ONLY)

    def test_schema_and_literal_synthetic_flag_never_coerce(self):
        for alternative in (False, 1, "true", None, [], {}):
            raw = packet()
            raw["synthetic_only"] = alternative
            self.assertIs(subject.review_batch(raw).status, subject.ReviewStatus.HOLD)
        raw = packet()
        raw["schema"] = subject.SCHEMA + ".2"
        self.assertIs(subject.review_batch(raw).status, subject.ReviewStatus.HOLD)

    def test_unknown_schema_fields_fail_closed(self):
        for name in ("issuer_id", "real_grant_id", "authorized", "consent"):
            raw = packet()
            raw[name] = "synthetic"
            self.assertIs(subject.review_batch(raw).status, subject.ReviewStatus.HOLD)
        raw = packet()
        raw["items"][0]["authorization_verified"] = True
        self.assertIs(subject.review_batch(raw).status, subject.ReviewStatus.HOLD)

    def test_batch_is_atomic_up_to_thirty_two(self):
        item = {"approved_by": "Synthetic Operator", "reference": "SYNTH-649"}
        self.assertIs(subject.review_batch(packet([dict(item)] * 32)).status, subject.ReviewStatus.REVIEW_ONLY)
        for pos in (0, 15, 31):
            rows = [dict(item) for _ in range(32)]
            rows[pos]["reference"] = ""
            self.assertIs(subject.review_batch(packet(rows)).status, subject.ReviewStatus.HOLD)
        for rows in ([], [dict(item)] * 33, tuple([item])):
            self.assertIs(subject.review_batch(packet(rows)).status, subject.ReviewStatus.HOLD)

    def test_json_rejects_duplicate_keys_and_nonfinite_values(self):
        for raw in (
            b'{"schema":"x","schema":"y"}',
            b'{"schema":"lightup.scope649.provenance.synthetic.v1","synthetic_only":true,"items":[{"approved_by":"a","approved_by":"b","reference":"x"}]}',
            encode(packet()).replace(b'true', b'NaN'),
            encode(packet()).replace(b'true', b'Infinity'),
            b'[1,2,3]',
            b'not-json',
            b'',
            b'\xff\xfe',
        ):
            with self.subTest(raw=raw[:40]):
                self.assertIs(subject.parse_and_review(raw).status, subject.ReviewStatus.HOLD)

    def test_json_size_limit_is_strict(self):
        self.assertIs(subject.parse_and_review(b"0" * (subject.MAX_STDIN + 1)).status, subject.ReviewStatus.HOLD)
        self.assertIs(subject.parse_and_review(bytearray(encode(packet()))).status, subject.ReviewStatus.HOLD)

    def test_cli_exits_never_zero_and_never_echoes_review_text(self):
        private = "SYNTH_SECRET_DO_NOT_ECHO"
        valid = encode(packet([{"approved_by": "Synthetic Operator", "reference": private}]))
        for raw, expected_status, expected_code in (
            (valid, "REVIEW_ONLY", 3),
            (b'{}', "HOLD", 2),
            (valid + b"0" * subject.MAX_STDIN, "HOLD", 2),
        ):
            with self.subTest(status=expected_status):
                proc = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                    input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=12, check=False,
                )
                self.assertEqual(proc.returncode, expected_code)
                self.assertEqual(proc.stderr, b"")
                self.assertNotIn(private.encode(), proc.stdout)
                out = json.loads(proc.stdout)
                self.assertEqual(out["status"], expected_status)
                self.assertTrue(all(
                    value is False for key, value in out.items() if key != "status"
                ))
                self.assertEqual(set(out) - {"status"}, {
                    "authorization_verified", "consent_verified", "permit_issued",
                    "dispatch_allowed", "execution_enabled", "merge_approved",
                    "release_approved",
                })

    def test_stdout_partial_or_failed_write_never_claims_review_receipt(self):
        class Stdin:
            class buffer:
                @staticmethod
                def read(n):
                    return encode(packet())
        with patch.object(subject.sys, "stdin", Stdin()):
            for result in (0, 1, None, True):
                with patch.object(subject.os, "write", return_value=result):
                    self.assertEqual(subject.main(), 2)
            with patch.object(subject.os, "write", side_effect=BrokenPipeError("SYNTH_SECRET")):
                self.assertEqual(subject.main(), 2)

    def test_stdin_errors_are_generic_hold_without_exposing_private_input(self):
        class BadStdin:
            class buffer:
                @staticmethod
                def read(n):
                    raise OSError("SYNTH_PRIVATE_MARKER")
        with patch.object(subject.sys, "stdin", BadStdin()):
            with patch.object(subject.os, "write", return_value=len(subject._HOLD)) as sink:
                self.assertEqual(subject.main(), 2)
                self.assertEqual(sink.call_args.args[1], subject._HOLD)
                self.assertNotIn(b"SYNTH_PRIVATE_MARKER", sink.call_args.args[1])

    def test_no_production_or_network_wiring(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for banned in ("from lightup", "import lightup", "socket.", "requests.",
                       "subprocess.", "sqlite3.", "urllib.", "http.client"):
            self.assertNotIn(banned, text)


if __name__ == "__main__":
    unittest.main()
