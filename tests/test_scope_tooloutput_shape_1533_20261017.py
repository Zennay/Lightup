"""Issue #1533: synthetic review PASS and original production contract RED.

Safe, stdlib-only; no StateStore, handlers, sockets, active targets or grants.
Set LIGHTUP_SCOPE1533_REQUIRE_SOURCE_FIX=1 to require actual source fixes.
"""
from __future__ import annotations

import ast
import copy
import os
import pickle
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lightup.ai.orchestration import OrchestrationError, ToolOutput
from lightup.scope_tooloutput_shape_review_20261017 import OutputIdentityReview, review_output_identity, review_output_batch

STRICT = os.environ.get("LIGHTUP_SCOPE1533_REQUIRE_SOURCE_FIX") == "1"
source_red = (lambda f: f) if STRICT else unittest.expectedFailure


class OfflineOutputReviewTests(unittest.TestCase):
    def test_valid_plain_fields_are_review_only_not_authority(self):
        self.assertEqual(review_output_identity("synthetic summary", "note", b""), OutputIdentityReview.REVIEW_ONLY)
        self.assertEqual(review_output_identity("synthetic summary", "note", b"x"), OutputIdentityReview.REVIEW_ONLY)
        self.assertNotEqual(review_output_identity("synthetic summary", "note", b"x"), "AUTHORIZED")
        self.assertNotEqual(review_output_identity("synthetic summary", "note", b"x"), "REVIEW_ONLY")

    def test_statuses_are_immutable_and_always_falsy(self):
        for fields, status in [
            (("ok", "note", b"x"), OutputIdentityReview.REVIEW_ONLY),
            (("ok", "note", "bad"), OutputIdentityReview.HOLD),
        ]:
            with self.subTest(status=status):
                value = review_output_identity(*fields)
                self.assertIs(value, status)
                self.assertFalse(value, "review receipt may not act as authorization")
                self.assertFalse(bool(value))
                self.assertEqual(value.value, status.value)
                self.assertNotIsInstance(value, str, "review status must not be accepted as string authority")
                self.assertNotEqual(value, value.value, "string comparisons cannot imply grant")
                self.assertNotEqual(value, "AUTHORIZED")
                for property_name in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
                    self.assertIs(getattr(value, property_name), False)
                for cloned in (copy.copy(value), copy.deepcopy(value), pickle.loads(pickle.dumps(value))):
                    self.assertIs(cloned, value)
                    self.assertFalse(cloned)
                    self.assertIs(cloned.dispatch_allowed, False)
                    self.assertIs(cloned.release_allowed, False)
        with self.assertRaises(AttributeError):
            OutputIdentityReview.HOLD.value = "AUTHORIZED"

    def test_canonical_installed_worker_output_kinds_without_execution(self):
        expected = {
            "http_baseline.py": "http-baseline-observation",
            "service_inventory.py": "service-inventory-observation",
            "tls_baseline.py": "tls-baseline-observation",
        }
        for filename, kind in expected.items():
            with self.subTest(worker=filename):
                path = ROOT / "src/lightup/workers" / filename
                tree = ast.parse(path.read_text(encoding="utf-8"))
                found = [
                    keyword.value.value
                    for call in ast.walk(tree) if isinstance(call, ast.Call)
                    for keyword in call.keywords
                    if keyword.arg == "evidence_kind" and isinstance(keyword.value, ast.Constant)
                    and type(keyword.value.value) is str
                ]
                self.assertIn(kind, found)
                self.assertIs(review_output_identity("synthetic", kind, b""), OutputIdentityReview.REVIEW_ONLY)

    def test_review_budgets_and_canonical_kinds(self):
        self.assertIs(review_output_identity("x" * 16_384, "a" * 80, b"x" * 4_194_304),
                      OutputIdentityReview.REVIEW_ONLY)
        for fields in [
            ("x" * 16_385, "note", b""),
            ("x", "a" * 81, b""),
            ("x", "note", b"x" * 4_194_305),
            ("x", "note\\u202e", b""),
            ("x", "note\\x00", b""),
            ("x", "note\\n", b""),
            ("x", "Note", b""),
        ]:
            self.assertIs(review_output_identity(*fields), OutputIdentityReview.HOLD)

    def test_no_identity_or_authority_upgrade_under_deterministic_kind_mutations(self):
        # Synthetic metadata only; never dispatch actual workers.
        accepted = "http-baseline-observation"
        self.assertIs(review_output_identity("synthetic", accepted, b"x"), OutputIdentityReview.REVIEW_ONLY)
        for index in range(len(accepted)):
            for replacement in ("\\x00", "\\n", "\\r", "\\t", "\\u200b", "\\u202e", "\\u2066", "/",
                                ":", "\\", "A", "9" if index == 0 else "@"):
                changed = accepted[:index] + replacement + accepted[index + 1:]
                if changed == accepted:
                    continue
                with self.subTest(position=index, char=ascii(replacement)):
                    result = review_output_identity("synthetic", changed, b"x")
                    self.assertIs(result, OutputIdentityReview.HOLD)
                    self.assertIs(result.authorized, False)
                    self.assertIs(result.consent_verified, False)
                    self.assertIs(result.dispatch_allowed, False)
                    self.assertIs(result.release_allowed, False)


    def test_batch_requires_exact_bounded_plain_tuple(self):
        good = ("synthetic", "note", b"x")
        invalid = [[], {}, set(), None, "", b"x", (), (good,) * 33,
                   [good], [good] * 32, (good, ("bad",)), (("synthetic", "note"),),
                   ((("synthetic", "note", b"x", "extra")),)]
        for value in invalid:
            with self.subTest(label=type(value).__name__, count=len(value) if hasattr(value, "__len__") else None):
                self.assertIs(review_output_batch(value), OutputIdentityReview.HOLD)
        for n in (1, 2, 16, 32):
            self.assertIs(review_output_batch((good,) * n), OutputIdentityReview.REVIEW_ONLY)
        self.assertIs(review_output_batch((good,) * 33), OutputIdentityReview.HOLD)

    def test_batch_atomic_hold_for_invalid_entry_at_every_position(self):
        canonical = ("synthetic", "http-baseline-observation", b"fixture")
        for size in (1, 2, 16, 32):
            for position in range(size):
                rows = [canonical] * size
                rows[position] = ("synthetic", "note\\nforged", b"fixture")
                before = tuple(rows)
                receipt = review_output_batch(tuple(rows))
                self.assertIs(receipt, OutputIdentityReview.HOLD)
                self.assertFalse(receipt)
                self.assertIs(receipt.authorized, False)
                self.assertIs(receipt.dispatch_allowed, False)
                self.assertEqual(tuple(rows), before)

    def test_batch_rejects_foreign_iterable_without_touching_protocols(self):
        visited = []
        class HostileSequence:
            def __iter__(self):
                visited.append("iter")
                raise AssertionError("foreign iterator invoked")
            def __len__(self):
                visited.append("len")
                raise AssertionError("foreign length invoked")
        class ForeignTuple(tuple):
            def __iter__(self):
                visited.append("foreign tuple iter")
                raise AssertionError("foreign tuple iter")
        self.assertIs(review_output_batch(HostileSequence()), OutputIdentityReview.HOLD)
        self.assertIs(review_output_batch(ForeignTuple((("x", "note", b"y"),))), OutputIdentityReview.HOLD)
        self.assertIs(review_output_batch(((HostileSequence(), "note", b"y"),)), OutputIdentityReview.HOLD)
        self.assertEqual(visited, [])

    def test_batch_supports_all_three_installed_worker_evidence_kinds(self):
        kinds = ("http-baseline-observation", "service-inventory-observation", "tls-baseline-observation")
        batch = tuple(("synthetic", kind, b"synthetic") for kind in kinds)
        receipt = review_output_batch(batch)
        self.assertIs(receipt, OutputIdentityReview.REVIEW_ONLY)
        self.assertFalse(receipt)
        for property_name in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(receipt, property_name), False)

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
            ("ok", "note" + "\\x00", b"x"),
            ("ok", "note\\nforged", b"x"),
            ("ok", "note\\u202e", b"x"),
            ("ok", "NOTE", b"x"),
            ("ok", "9note", b"x"),
            ("ok", ".note", b"x"),
            ("ok", "note:evil", b"x"),
            ("ok", "note\\u200b", b"x"),
            ("ok", "n" * 81, b"x"),
            ("x" * 16_385, "note", b"x"),
            ("ok", "note", b"x" * 4_194_305),
        ]
        for fields in values:
            with self.subTest(fields=tuple(type(v).__name__ for v in fields)):
                self.assertEqual(review_output_identity(*fields), OutputIdentityReview.HOLD)

    def test_reject_subclass_scalar_claims_without_coercion(self):
        class StrangeStr(str):
            def strip(self, *args, **kwargs):
                raise AssertionError("untrusted subclass method invoked")
        class StrangeBytes(bytes):
            def __bytes__(self):
                raise AssertionError("unexpected coercion")
        self.assertEqual(review_output_identity(StrangeStr("ok"), "note", b"x"), OutputIdentityReview.HOLD)
        self.assertEqual(review_output_identity("ok", StrangeStr("note"), b"x"), OutputIdentityReview.HOLD)
        self.assertEqual(review_output_identity("ok", "note", StrangeBytes(b"x")), OutputIdentityReview.HOLD)

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
            self.assertEqual(review_output_identity(*args), OutputIdentityReview.HOLD)
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

    @source_red
    def test_source_red_summary_str_subclass(self):
        class ForgedSummary(str):
            pass
        self.assert_source_rejects(summary=ForgedSummary("synthetic"))

    @source_red
    def test_source_red_evidence_kind_str_subclass(self):
        class ForgedKind(str):
            pass
        self.assert_source_rejects(evidence_kind=ForgedKind("note"))

    @source_red
    def test_source_red_payload_bytes_subclass(self):
        class ForgedPayload(bytes):
            pass
        self.assert_source_rejects(evidence_payload=ForgedPayload(b"payload"))


if __name__ == "__main__":
    unittest.main()
