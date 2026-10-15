"""Synthetic #1147 source-owner integration contract; NO source/runtime changes.

This is a bounded in-memory simulation of one *possible* owner-side repair.
Patch only the installed ToolCall.arguments_dict method during inert tests.
All source files, actual permissions, grant decisions and target adapters remain
unchanged. The source owner must independently implement and validate the fix.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from lightup.ai.orchestration import OrchestrationError, ToolCall

from test_scope_1147_expected_red_integrity_20261015 import (
    EXPECTED_ORDINARY_CONTROL_NAMES,
    EXPECTED_SOURCE_RED,
)


def _strict_preprojection(call: ToolCall) -> dict[str, object]:
    """Reference contract only: reject duplicate *exact* names before dict.

    This is deliberately not a production implementation or authorization
    decision. Name-type/alias canonicalization belongs to separate owners.
    """
    seen: set[str] = set()
    projected: dict[str, object] = {}
    for name, value in call.arguments:
        if name in seen:
            raise OrchestrationError("fictional-fixture: duplicate argument name")
        seen.add(name)
        projected[name] = value
    return projected


def _fixture():
    # Local import prevents unittest discovery accidentally collecting 25
    # original source cases a second time from this module.
    from test_scope_1147_duplicate_key_installed_matrix_20261015 import (
        DuplicateArgumentKeysInstalledSource1147,
    )
    return DuplicateArgumentKeysInstalledSource1147


class Scope1147OwnerIntegrationTransitionTests(unittest.TestCase):
    def _run_installed_case_without_xfail_wrapper(self, name: str) -> None:
        fixture = _fixture()(name)
        fixture.setUp()
        try:
            # Direct invocation purposefully ignores @expectedFailure metadata.
            # A future real fix must turn the nine missing-denial assertions
            # into ordinary PASS rather than keep xfail status forever.
            getattr(fixture, name)()
        finally:
            fixture.doCleanups()

    def test_all_nine_current_source_red_become_plain_pass_under_isolated_fix(self):
        self.assertEqual(len(EXPECTED_SOURCE_RED), 9)
        with patch.object(ToolCall, "arguments_dict", _strict_preprojection):
            for name in sorted(EXPECTED_SOURCE_RED):
                with self.subTest(original_red=name):
                    self._run_installed_case_without_xfail_wrapper(name)

    def test_all_eight_safe_controls_still_pass_after_synthetic_fix(self):
        safe = sorted(
            name for name in EXPECTED_ORDINARY_CONTROL_NAMES
            if not name.startswith("test_current_source_")
        )
        self.assertEqual(len(safe), 8)
        with patch.object(ToolCall, "arguments_dict", _strict_preprojection):
            for name in safe:
                with self.subTest(control=name):
                    self._run_installed_case_without_xfail_wrapper(name)

    def test_eight_unsafe_positive_witnesses_must_be_retired_after_real_fix(self):
        witnesses = sorted(
            name for name in EXPECTED_ORDINARY_CONTROL_NAMES
            if name.startswith("test_current_source_")
        )
        self.assertEqual(len(witnesses), 8)
        with patch.object(ToolCall, "arguments_dict", _strict_preprojection):
            for name in witnesses:
                with self.subTest(obsolete_source_witness=name):
                    with self.assertRaises(OrchestrationError):
                        self._run_installed_case_without_xfail_wrapper(name)

    def test_original_unmodified_main_implementation_is_restored_after_patch(self):
        original_method = ToolCall.arguments_dict
        call = ToolCall(
            tool_id="fixture-analysis", asset="fixture-only.invalid",
            arguments=(("selector", "first"), ("selector", "last")),
        )
        self.assertEqual(call.arguments_dict(), {"selector": "last"})
        with patch.object(ToolCall, "arguments_dict", _strict_preprojection):
            self.assertIs(ToolCall.arguments_dict, _strict_preprojection)
            with self.assertRaises(OrchestrationError):
                call.arguments_dict()
        self.assertIs(ToolCall.arguments_dict, original_method)
        self.assertEqual(call.arguments_dict(), {"selector": "last"})

    def test_unique_values_preserve_exact_typed_identity_in_simulation(self):
        marker = object()
        call = ToolCall(
            tool_id="fixture-analysis", asset="fixture-only.invalid",
            arguments=(("selector", "preserved"), ("note", marker)),
        )
        with patch.object(ToolCall, "arguments_dict", _strict_preprojection):
            result = call.arguments_dict()
        self.assertEqual(tuple(result), ("selector", "note"))
        self.assertEqual(result["selector"], "preserved")
        self.assertIs(result["note"], marker)


if __name__ == "__main__":
    unittest.main()
