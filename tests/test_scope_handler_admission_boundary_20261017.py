"""Independent opt-in no-wiring and hostile metadata controls for #1531."""
from __future__ import annotations

import ast
import functools
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

    def test_mutated_function_code_requires_fresh_review(self):
        def candidate(context, arguments):
            return None
        def wrong_arity(context):
            return None
        original_code = candidate.__code__
        self.assertEqual(review_handlers((("candidate", candidate),)).status, "REVIEW_ONLY")
        try:
            candidate.__code__ = wrong_arity.__code__
            self.assertEqual(review_handlers((("candidate", candidate),)).status, "HOLD")
        finally:
            candidate.__code__ = original_code
        self.assertEqual(review_handlers((("candidate", candidate),)).status, "REVIEW_ONLY")

    def test_mutated_defaults_require_fresh_review(self):
        def candidate(context, arguments):
            return None
        self.assertEqual(review_handlers((("candidate", candidate),)).status, "REVIEW_ONLY")
        try:
            candidate.__defaults__ = (None,)
            self.assertEqual(review_handlers((("candidate", candidate),)).status, "HOLD")
        finally:
            candidate.__defaults__ = None
        self.assertEqual(review_handlers((("candidate", candidate),)).status, "REVIEW_ONLY")

    def test_callable_adapters_are_never_invoked_by_offline_review(self):
        class CallableTrap:
            def __call__(self, context, arguments):
                raise AssertionError("external callback must never execute")
        class BoundTrap:
            def execute(self, context, arguments):
                raise AssertionError("bound callback must never execute")
        for value in (CallableTrap(), BoundTrap().execute,
                      functools.partial(inert, None), len):
            with self.subTest(value=type(value).__name__):
                result = review_handlers((("candidate", value),))
                self.assertEqual(result.status, "HOLD")
                self.assertFalse(result.authorized)
                self.assertFalse(result.consent_verified)
                self.assertFalse(result.dispatch_allowed)
                self.assertFalse(result.release_allowed)

    def test_actual_project_worker_handler_shapes_without_dispatch(self):
        # Verify all three shipped workers, not only invented synthetic callbacks.
        # Module imports are local; workers themselves are NEVER invoked.
        from lightup.workers import http_baseline, service_inventory, tls_baseline
        from unittest import mock
        entries = (
            ("http_baseline", http_baseline.run_http_baseline),
            ("service_inventory", service_inventory.run_service_inventory),
            ("tls_baseline", tls_baseline.run_tls_baseline),
        )
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
            outcome = review_handlers(entries)
        self.assertEqual(outcome.status, "REVIEW_ONLY")
        self.assertFalse(outcome.authorized)
        self.assertFalse(outcome.consent_verified)
        self.assertFalse(outcome.dispatch_allowed)
        self.assertFalse(outcome.release_allowed)

    def test_actual_worker_registry_compatibility_without_handler_execution(self):
        # Guard a source-owner repair from breaking the 3 stock worker bindings.
        from lightup.ai.orchestration import ToolRegistry
        from lightup.workers import http_baseline, service_inventory, tls_baseline
        from unittest import mock
        modules = (http_baseline, service_inventory, tls_baseline)
        handlers = (
            http_baseline.run_http_baseline,
            service_inventory.run_service_inventory,
            tls_baseline.run_tls_baseline,
        )
        registry = ToolRegistry()
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
            for module in modules:
                module.register(registry)
        self.assertEqual(len(registry.definitions()), len(modules))
        self.assertEqual(
            tuple(registry.get(module.TOOL_ID)[1] for module in modules), handlers
        )

    def test_strict_owner_gate_requires_literal_one_not_truthy_tokens(self):
        from unittest import mock
        from test_scope_handler_admission_20261017 import source_red_until_owner_fix
        for token in ("", "0", "True", "true", "yes", "01", " 1", "1 ", "2"):
            with self.subTest(token=repr(token)):
                # unittest.expectedFailure mutates the function object. Use
                # fresh functions to avoid making strict tests false-positive.
                def nonstrict_sample(self):
                    return None
                with mock.patch.dict("os.environ", {"LIGHTUP_SCOPE1531_REQUIRE_SOURCE_FIX": token}):
                    decorated = source_red_until_owner_fix(nonstrict_sample)
                self.assertTrue(
                    getattr(decorated, "__unittest_expecting_failure__", False),
                    "nonliteral token must not enable strict mode",
                )
        def strict_sample(self):
            return None
        with mock.patch.dict("os.environ", {"LIGHTUP_SCOPE1531_REQUIRE_SOURCE_FIX": "1"}):
            strict = source_red_until_owner_fix(strict_sample)
        self.assertIs(strict, strict_sample)
        self.assertFalse(getattr(strict, "__unittest_expecting_failure__", False))

    def test_source_gate_decoration_never_invokes_a_handler(self):
        from unittest import mock
        from test_scope_handler_admission_20261017 import source_red_until_owner_fix
        def trap(self):
            raise AssertionError("untrusted source handler must never run")
        with mock.patch.dict("os.environ", {"LIGHTUP_SCOPE1531_REQUIRE_SOURCE_FIX": "1"}):
            self.assertIs(source_red_until_owner_fix(trap), trap)
        with mock.patch.dict("os.environ", {"LIGHTUP_SCOPE1531_REQUIRE_SOURCE_FIX": "0"}):
            decorated = source_red_until_owner_fix(trap)
        self.assertTrue(getattr(decorated, "__unittest_expecting_failure__", False))

    def test_async_and_generator_code_substitution_forces_fresh_hold(self):
        # A previously shape-valid Python function can acquire async or
        # generator code without replacing the function object.
        def candidate(context, arguments):
            return None
        async def coroutine(context, arguments):
            return None
        def generator(context, arguments):
            yield None
        async def async_generator(context, arguments):
            yield None

        original_code = candidate.__code__
        self.assertEqual(review_handlers((("candidate", candidate),)).status, "REVIEW_ONLY")
        try:
            for alternate in (coroutine, generator, async_generator):
                with self.subTest(code=alternate.__name__):
                    candidate.__code__ = alternate.__code__
                    receipt = review_handlers((("candidate", candidate),))
                    self.assertEqual(receipt.status, "HOLD")
                    self.assertFalse(receipt.authorized)
                    self.assertFalse(receipt.consent_verified)
                    self.assertFalse(receipt.dispatch_allowed)
                    self.assertFalse(receipt.release_allowed)
        finally:
            candidate.__code__ = original_code
        self.assertEqual(review_handlers((("candidate", candidate),)).status, "REVIEW_ONLY")

    def test_keyword_defaults_mutation_forces_fresh_hold(self):
        def candidate(context, arguments):
            return None

        original_defaults = candidate.__kwdefaults__
        self.assertEqual(review_handlers((("candidate", candidate),)).status, "REVIEW_ONLY")
        try:
            candidate.__kwdefaults__ = {"arguments": None}
            receipt = review_handlers((("candidate", candidate),))
            self.assertEqual(receipt.status, "HOLD")
            self.assertFalse(receipt.dispatch_allowed)
        finally:
            candidate.__kwdefaults__ = original_defaults
        self.assertEqual(review_handlers((("candidate", candidate),)).status, "REVIEW_ONLY")

    def test_opaque_annotations_are_not_reflected_or_executed(self):
        class MetadataTrap:
            def __getattribute__(self, key):
                raise AssertionError("annotation reflection forbidden")
            def __repr__(self):
                raise AssertionError("annotation presentation forbidden")
        def candidate(context, arguments):
            return None
        original_annotations = candidate.__annotations__
        try:
            candidate.__annotations__ = {"context": MetadataTrap()}
            receipt = review_handlers((("candidate", candidate),))
            self.assertEqual(receipt.status, "REVIEW_ONLY")
            self.assertFalse(receipt.authorized)
            self.assertFalse(receipt.consent_verified)
            self.assertFalse(receipt.dispatch_allowed)
            self.assertFalse(receipt.release_allowed)
        finally:
            candidate.__annotations__ = original_annotations


if __name__ == "__main__":
    unittest.main()
