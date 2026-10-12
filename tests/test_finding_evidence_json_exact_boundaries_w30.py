"""W30 exact boundary acceptance for the optional persisted evidence decoder.

No production read-path wiring, SQLite mutations or target interaction.
"""
from __future__ import annotations

import json
import unittest

from lightup.finding_evidence_json_checked_optin_w27 import (
    decode_finding_evidence_checked,
)

_ERROR = "invalid persisted finding evidence integrity"


class W30PersistedEvidenceDecoderBoundaryTests(unittest.TestCase):
    def assert_invalid(self, raw):
        with self.assertRaises(ValueError) as raised:
            decode_finding_evidence_checked(raw)
        self.assertEqual(str(raised.exception), _ERROR)

    def test_exact_262144_byte_json_accepts_distinct_128_refs(self):
        # JSON structural overhead: 2 brackets + 256 quotes + 127 commas.
        refs = [f"{i:03d}:" + "x" * 2041 for i in range(127)]
        refs.append("127:" + "x" * 2040)
        raw = json.dumps(refs, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(len(raw.encode("utf-8")), 262144)
        self.assertEqual(len(set(refs)), 128)
        self.assertEqual(decode_finding_evidence_checked(raw), tuple(refs))

    def test_one_byte_over_json_budget_denied_before_parse(self):
        refs = [f"{i:03d}:" + "x" * 2041 for i in range(127)]
        refs.append("127:" + "x" * 2040)
        raw = json.dumps(refs, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(len(raw.encode("utf-8")), 262144)
        self.assert_invalid(raw + " ")

    def test_exact_reference_utf8_byte_limit(self):
        ref = "é" * 2048
        self.assertEqual(len(ref.encode("utf-8")), 4096)
        raw = json.dumps([ref], ensure_ascii=False)
        self.assertEqual(decode_finding_evidence_checked(raw), (ref,))

    def test_one_codepoint_over_reference_byte_limit(self):
        ref = "é" * 2049
        self.assertEqual(len(ref.encode("utf-8")), 4098)
        self.assert_invalid(json.dumps([ref], ensure_ascii=False))

    def test_distinct_128_refs_accepted_and_129th_denied(self):
        refs = [f"evidence:{i}" for i in range(128)]
        self.assertEqual(decode_finding_evidence_checked(json.dumps(refs)), tuple(refs))
        self.assert_invalid(json.dumps(refs + ["evidence:128"]))

    def test_unicode_escape_alias_duplicate_refuses(self):
        # JSON escapes decode to the same exact reference and cannot be counted twice.
        self.assert_invalid('["evidence:alpha","evidence\\u003aalpha"]')

    def test_exact_distinct_unicode_references_keep_bytes_and_order(self):
        refs = ["évidence:alpha", "e\u0301vidence:alpha", "Evidence:ALPHA", "evidence:alpha "]
        raw = json.dumps(refs, ensure_ascii=False)
        self.assertEqual(decode_finding_evidence_checked(raw), tuple(refs))
        self.assertEqual(refs[0], "évidence:alpha")
        self.assertNotEqual(refs[0], refs[1])

    def test_surrogate_and_nested_constants_collapse_to_generic_error(self):
        for raw in (
            '["\\ud800"]',
            '["\\udfff"]',
            '["valid",NaN]',
            '["valid",Infinity]',
            '["valid",-Infinity]',
        ):
            with self.subTest(raw=raw):
                self.assert_invalid(raw)

    def test_empty_list_and_whitespace_are_compatible(self):
        self.assertEqual(decode_finding_evidence_checked(" \n [] \t"), ())

    def test_outer_type_is_exact_built_in_string(self):
        class FancyString(str):
            pass
        for value in (FancyString("[]"), [], None, b"[]", {"raw": "[]"}):
            with self.subTest(value=repr(value)):
                self.assert_invalid(value)


if __name__ == "__main__":
    unittest.main()
