"""Independent opt-in no-wiring and hostile metadata controls for #1531."""
from __future__ import annotations

import ast
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_handler_admission_review_20261017 import review_handlers

HELPER_NAME = "scope_handler_admission_review_20261017"


def inert(context, arguments):
    raise AssertionError("offline gate must not dispatch any handler")


class ReviewBoundaryTests(unittest.TestCase):
    def test_no_static_production_source_imports(self):
        # AST import review, not a claim that reflection or generated imports cannot exist.
        files = sorted((ROOT / "src" / "lightup").rglob("*.py"))
        self.assertGreater(len(files), 0)
        for file in files:
            tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertFalse(
                        any(part.name == HELPER_NAME or part.name.endswith("." + HELPER_NAME)
                            for part in node.names), str(file)
                    )
                elif isinstance(node, ast.ImportFrom):
                    self.assertFalse(
                        (node.module or "").endswith(HELPER_NAME)
                        or any(part.name == HELPER_NAME for part in node.names),
                        str(file)
                    )

    def test_exact_tuple_only_even_for_trap_subclasses(self):
        class Trap(tuple):
            def __len__(self):
                raise AssertionError("tuple subclass length must never execute")
            def __iter__(self):
                raise AssertionError("tuple subclass iterator must never execute")
        class Evasive:
            def __getattribute__(self, name):
                raise AssertionError("foreign reflection must never execute")
        for value in (Trap((("a", inert),)), (Trap(("a", inert)),), (("a", Evasive()),)):
            result = review_handlers(value)
            self.assertEqual(result.status, "HOLD")
            self.assertFalse(result.dispatch_allowed)
            self.assertFalse(result.authorized)

    def test_every_single_ascii_character_in_identifier_is_reviewed(self):
        for i in range(128):
            value = "h" + chr(i)
            with self.subTest(i=i):
                verdict = review_handlers(((value, inert),))
                self.assertIn(verdict.status, ("REVIEW_ONLY", "HOLD"))
                self.assertEqual(verdict.status, "REVIEW_ONLY" if chr(i) in "abcdefghijklmnopqrstuvwxyz0123456789_" else "HOLD")
                self.assertFalse(verdict.authorized)
                self.assertFalse(verdict.consent_verified)
                self.assertFalse(verdict.dispatch_allowed)
                self.assertFalse(verdict.release_allowed)

    def test_full_batch_atomicity(self):
        for bad in ("a-b", "A", "!", "\x00", "λ", ""):
            with self.subTest(bad=repr(bad)):
                rows = tuple((f"a_{i}", inert) for i in range(31)) + ((bad, inert),)
                self.assertEqual(review_handlers(rows).status, "HOLD")


if __name__ == "__main__":
    unittest.main()
