"""No-network, no-execution acceptance for opt-in scope #1531 reviewer."""
from __future__ import annotations

import dataclasses
import os
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from scope_handler_admission_review_20261017 import review_handlers
from lightup.ai.orchestration import (
    OrchestrationError, ToolDefinition, ToolRegistry,
)
from lightup.capabilities import get_capabilities
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind


def source_red_until_owner_fix(test):
    """Promote original source REDs to ordinary mandatory tests only in strict mode.

    Default behavior records known unchanged-production gaps as expected failures.
    An explicit literal 1 changes source REDs into ordinary tests so source owners
    can verify their actual patch without changing test code or this PR.
    """
    if os.environ.get("LIGHTUP_SCOPE1531_REQUIRE_SOURCE_FIX") == "1":
        return test
    return unittest.expectedFailure(test)


def inert_handler(context, arguments):
    raise AssertionError("handler must not be invoked in an offline test")


def second_handler(context, arguments):
    raise AssertionError("handler must not be invoked")


def one_arg(context):
    raise AssertionError("wrong signature must never execute")


def three_args(context, arguments, extra):
    raise AssertionError("wrong signature must never execute")


def default_arg(context, arguments=None):
    raise AssertionError("ambiguous default must never execute")


def varargs_handler(context, *args):
    raise AssertionError("variadic function must never execute")


def keyword_only(context, *, arguments):
    raise AssertionError("keyword-only function must never execute")


async def async_handler(context, arguments):
    raise AssertionError("async handler must never execute")


def generator_handler(context, arguments):
    yield 1


class StrangeString(str):
    def __hash__(self):
        raise AssertionError("subclass hash executed")


class HandlerAdmissionReviewTests(unittest.TestCase):
    def assert_hold(self, records):
        review = review_handlers(records)
        self.assertEqual(review.status, "HOLD")
        self.assertFalse(review.authorized)
        self.assertFalse(review.consent_verified)
        self.assertFalse(review.dispatch_allowed)
        self.assertFalse(review.release_allowed)

    def test_canonical_one(self):
        review = review_handlers((("a", inert_handler),))
        self.assertEqual(review.status, "REVIEW_ONLY")
        self.assertFalse(review.authorized)
        self.assertFalse(review.consent_verified)
        self.assertFalse(review.dispatch_allowed)
        self.assertFalse(review.release_allowed)

    def test_canonical_multiple(self):
        self.assertEqual(review_handlers((("a", inert_handler), ("b_2", second_handler))).status, "REVIEW_ONLY")

    def test_max_boundary(self):
        self.assertEqual(review_handlers(tuple((f"h_{i}", inert_handler) for i in range(32))).status, "REVIEW_ONLY")
        self.assert_hold(tuple((f"h_{i}", inert_handler) for i in range(33)))

    def test_malformed_top_level(self):
        for value in (None, (), [], {}, (("a", inert_handler) for _ in range(1))):
            with self.subTest(value=type(value)):
                self.assert_hold(value)

    def test_malformed_row(self):
        for row in (["a", inert_handler], ("a",), ("a", inert_handler, 1), None, {}):
            with self.subTest(row=type(row)):
                self.assert_hold((row,))

    def test_bad_names(self):
        for value in ("", "_", "A", "a-b", "a b", "a\x00", "a\n", "á", "a"*65, 4, True, StrangeString("a")):
            with self.subTest(value=repr(value)):
                self.assert_hold(((value, inert_handler),))

    def test_duplicate_name(self):
        self.assert_hold((("a", inert_handler), ("a", second_handler)))

    def test_noncallable(self):
        for value in (None, 0, "", {}, object()):
            with self.subTest(value=type(value)):
                self.assert_hold((("x", value),))

    def test_callable_objects_do_not_execute(self):
        class Trap:
            def __call__(self, *args, **kwargs):
                raise AssertionError("must not invoke")
        self.assert_hold((("x", Trap()),))

    def test_wrong_arity(self):
        for handler in (one_arg, three_args, default_arg, varargs_handler, keyword_only):
            with self.subTest(handler=handler.__name__):
                self.assert_hold((("x", handler),))

    def test_async_and_generator_are_never_accepted(self):
        self.assert_hold((("x", async_handler),))
        self.assert_hold((("x", generator_handler),))

    def test_closure_rejected(self):
        secret = object()
        def nested(context, arguments):
            return secret
        self.assert_hold((("x", nested),))

    def test_non_authorizing_status_constructor(self):
        from scope_handler_admission_review_20261017 import HandlerAdmissionReview
        with self.assertRaises(TypeError):
            HandlerAdmissionReview("REVIEW_ONLY", authorized=True)
        self.assertTrue(dataclasses.is_dataclass(HandlerAdmissionReview))

    def test_review_receipt_rejects_forged_statuses(self):
        from scope_handler_admission_review_20261017 import HandlerAdmissionReview
        class Deceptive(str):
            def __eq__(self, other):
                raise AssertionError("subclass comparison must never run")
        for forged in ("APPROVED", "AUTHORIZED", "", None, True, 0, Deceptive("REVIEW_ONLY")):
            with self.subTest(forged=type(forged).__name__):
                with self.assertRaises(ValueError):
                    HandlerAdmissionReview(forged)

    def test_purity_input_does_not_change(self):
        records = (("x", inert_handler),)
        before = tuple(records)
        for _ in range(20):
            self.assertEqual(review_handlers(records).status, "REVIEW_ONLY")
        self.assertEqual(records, before)

    def test_review_is_independent_of_prior_result_mutation(self):
        result = review_handlers((("x", inert_handler),))
        object.__setattr__(result, "authorized", True)
        self.assertFalse(review_handlers((("x", inert_handler),)).authorized)

    def test_no_file_process_or_network_io(self):
        with mock.patch("builtins.open", side_effect=AssertionError("opened file")), \
             mock.patch("socket.socket", side_effect=AssertionError("opened socket")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("spawned process")):
            self.assertEqual(review_handlers((("x", inert_handler),)).status, "REVIEW_ONLY")
            self.assert_hold((("x", None),))


class InstalledSourceAcceptanceTests(unittest.TestCase):
    """An intentionally open source RED is not a production fix."""

    def _definition(self, tool_id="scope_1531_synthetic"):
        return ToolDefinition(
            tool_id=tool_id, capability_id=get_capabilities()[0].capability_id,
            interaction=InteractionKind.ANALYSIS,
            min_risk=RiskLevel.ANALYSIS_ONLY,
            description="offline synthetic non-execution test",
        )

    def test_real_registry_accepts_canonical_inert_handler(self):
        reg = ToolRegistry()
        definition = self._definition()
        reg.register(definition, inert_handler)
        self.assertIs(reg.get(definition.tool_id)[1], inert_handler)
        self.assertEqual(reg.definitions(), (definition,))

    def test_real_registry_rejects_duplicate_tool_id_before_mutation(self):
        reg = ToolRegistry()
        definition = self._definition()
        reg.register(definition, inert_handler)
        with self.assertRaises(OrchestrationError):
            reg.register(definition, second_handler)
        self.assertIs(reg.get(definition.tool_id)[1], inert_handler)

    def test_duplicate_tool_id_denial_precedes_hostile_handler_reflection(self):
        # A duplicate registration must reject based on the registry key before
        # inspecting a foreign callable's metadata or replacing a good binding.
        class ReflectionTrap:
            @property
            def __signature__(self):
                raise AssertionError("no foreign signature inspection on duplicate")
            def __call__(self, context, arguments):
                raise AssertionError("no foreign callable execution on duplicate")
        reg = ToolRegistry()
        original = self._definition()
        reg.register(original, inert_handler)
        before = reg.definitions()
        with self.assertRaises(OrchestrationError):
            reg.register(original, ReflectionTrap())
        self.assertEqual(reg.definitions(), before)
        self.assertIs(reg.get(original.tool_id)[1], inert_handler)

    @source_red_until_owner_fix
    def test_source_red_noncallable_must_be_rejected_before_registration(self):
        reg = ToolRegistry()
        definition = self._definition()
        with self.assertRaises(OrchestrationError):
            reg.register(definition, None)
        self.assertEqual(reg.definitions(), ())

    @source_red_until_owner_fix
    def test_source_red_numeric_handler_must_be_rejected_atomically(self):
        reg = ToolRegistry()
        definition = self._definition()
        with self.assertRaises(OrchestrationError):
            reg.register(definition, 123)
        self.assertEqual(reg.definitions(), ())

    @source_red_until_owner_fix
    def test_source_red_wrong_handler_arity_must_fail_before_registry_mutation(self):
        reg = ToolRegistry()
        original = self._definition()
        reg.register(original, inert_handler)
        before = reg.definitions()
        candidate = self._definition("scope_1531_wrong_arity")
        with self.assertRaises(OrchestrationError):
            reg.register(candidate, one_arg)
        self.assertEqual(reg.definitions(), before)
        self.assertIs(reg.get(original.tool_id)[1], inert_handler)

    @source_red_until_owner_fix
    def test_source_red_async_handler_must_fail_before_registry_mutation(self):
        reg = ToolRegistry()
        original = self._definition()
        reg.register(original, inert_handler)
        before = reg.definitions()
        candidate = self._definition("scope_1531_async_handler")
        with self.assertRaises(OrchestrationError):
            reg.register(candidate, async_handler)
        self.assertEqual(reg.definitions(), before)
        self.assertIs(reg.get(original.tool_id)[1], inert_handler)

    @source_red_until_owner_fix
    def test_source_red_generator_handler_must_be_rejected_atomically(self):
        reg = ToolRegistry()
        definition = self._definition("scope_1531_generator")
        with self.assertRaises(OrchestrationError):
            reg.register(definition, generator_handler)
        self.assertEqual(reg.definitions(), ())

    @source_red_until_owner_fix
    def test_source_red_foreign_callable_signature_must_not_be_reflected(self):
        class SignatureTrap:
            @property
            def __signature__(self):
                raise AssertionError("untrusted signature property executed")

            def __call__(self, context, arguments):
                raise AssertionError("untrusted callback executed")

        reg = ToolRegistry()
        canonical = self._definition()
        reg.register(canonical, inert_handler)
        before = reg.definitions()
        with self.assertRaises(OrchestrationError):
            reg.register(self._definition("scope_1531_signature_trap"), SignatureTrap())
        self.assertEqual(reg.definitions(), before)
        self.assertIs(reg.get(canonical.tool_id)[1], inert_handler)


if __name__ == "__main__":
    unittest.main()
