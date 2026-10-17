"""Issue #1533: synthetic review PASS and original production contract RED.

Safe, stdlib-only; no StateStore, handlers, sockets, active targets or grants.
Set LIGHTUP_SCOPE1533_REQUIRE_SOURCE_FIX=1 to require actual source fixes.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lightup.ai.orchestration import OrchestrationError, ToolOutput
from lightup.scope_tooloutput_shape_review_20261017 import review_output_identity

STRICT = os.environ.get("LIGHTUP_SCOPE1533_REQUIRE_SOURCE_FIX") == "1"
source_red = (lambda f: f) if STRICT else unittest.expectedFailure


class OfflineOutputReviewTests(unittest.TestCase):
    def test_valid_plain_fields_are_review_only_not_authority(self):
        self.assertEqual(review_output_identity("synthetic summary", "note", b""), "REVIEW_ONLY")
        self.assertEqual(review_output_identity("synthetic summary", "note", b"x"), "REVIEW_ONLY")
        self.assertNotEqual(review_output_identity("synthetic summary", "note", b"x"), "AUTHORIZED")

    def test_malformed_fields_atomic_hold(self):
        values = [
            (123, "note", b"x"),
            ("", "note", b"x"),
            ("   ", "note", b"x"),
            ("ok", 12, b"x"),
            ("ok", "", b"x"),
            ("ok", "\n\t", b"x"),
            ("ok", "note", bytearray(b"x")),
            ("ok", "note", memoryview(b"x")),
            ("ok", "note", "bytes-as-text"),
            ("ok", "note", None),
            (None, "note", b"x"),
        ]
        for fields in values:
            with self.subTest(fields=tuple(type(v).__name__ for v in fields)):
                self.assertEqual(review_output_identity(*fields), "HOLD")

    def test_reject_subclass_scalar_claims_without_coercion(self):
        class StrangeStr(str):
            def strip(self, *args, **kwargs):
                raise AssertionError("untrusted subclass method invoked")
        class StrangeBytes(bytes):
            def __bytes__(self):
                raise AssertionError("unexpected coercion")
        self.assertEqual(review_output_identity(StrangeStr("ok"), "note", b"x"), "HOLD")
        self.assertEqual(review_output_identity("ok", StrangeStr("note"), b"x"), "HOLD")
        self.assertEqual(review_output_identity("ok", "note", StrangeBytes(b"x")), "HOLD")

    def test_no_foreign_protocols_or_handler_invocation(self):
        observed = []
        class Trap:
            def __str__(self):
                observed.append("str")
                raise AssertionError("str called")
            def __bytes__(self):
                observed.append("bytes")
                raise AssertionError("bytes called")
            def __iter__(self):
                observed.append("iter")
                raise AssertionError("iter called")
        for args in [(Trap(), "note", b"x"), ("ok", Trap(), b"x"), ("ok", "note", Trap())]:
            self.assertEqual(review_output_identity(*args), "HOLD")
        self.assertEqual(observed, [])

    def test_review_is_not_imported_by_original_product_surfaces(self):
        helper_name = "scope_tooloutput_shape_review_20261017"
        for path in [
            ROOT / "src/lightup/ai/orchestration.py",
            ROOT / "src/lightup/state.py",
            ROOT / "src/lightup/execution_policy.py",
        ]:
            source = path.read_text(encoding="utf-8")
            imports = [n for n in ast.walk(ast.parse(source)) if isinstance(n, (ast.Import, ast.ImportFrom))]
            self.assertTrue(all(helper_name not in ast.get_source_segment(source, n) for n in imports))

    def test_source_positive_canonical_tooloutput_fields(self):
        output = ToolOutput("synthetic", "note", b"payload")
        self.assertEqual((output.summary, output.evidence_kind, output.evidence_payload),
                         ("synthetic", "note", b"payload"))

    def assert_source_rejects(self, **changes):
        data = dict(summary="synthetic", evidence_kind="note", evidence_payload=b"payload")
        data.update(changes)
        with self.assertRaises(OrchestrationError):
            ToolOutput(**data)

    @source_red
    def test_source_red_nonstring_summary(self):
        self.assert_source_rejects(summary=123)

    @source_red
    def test_source_red_blank_summary(self):
        self.assert_source_rejects(summary=" \t ")

    @source_red
    def test_source_red_nonstring_evidence_kind(self):
        self.assert_source_rejects(evidence_kind=123)

    @source_red
    def test_source_red_blank_evidence_kind(self):
        self.assert_source_rejects(evidence_kind="\n")

    @source_red
    def test_source_red_mutable_payload(self):
        self.assert_source_rejects(evidence_payload=bytearray(b"payload"))

    @source_red
    def test_source_red_text_payload(self):
        self.assert_source_rejects(evidence_payload="not bytes")


if __name__ == "__main__":
    unittest.main()
