"""Fail-closed regression: tool argument keys may not be silently overwritten.

Offline only: no handlers, networking, targets, or evidence writes.
"""
import unittest

from lightup.ai.orchestration import ToolCall, OrchestrationError


class ToolCallDuplicateArgumentsTests(unittest.TestCase):
    def test_duplicate_key_must_not_silently_change_requested_value(self):
        call = ToolCall(
            tool_id="offline-example",
            asset="offline.invalid",
            arguments=(("limit", 1), ("limit", 1000)),
        )
        with self.assertRaises((OrchestrationError, ValueError)):
            call.arguments_dict()

    def test_identical_duplicate_key_is_also_ambiguous(self):
        call = ToolCall(
            tool_id="offline-example",
            asset="offline.invalid",
            arguments=(("limit", 1), ("limit", 1)),
        )
        with self.assertRaises((OrchestrationError, ValueError)):
            call.arguments_dict()

    def test_duplicate_cannot_hide_malformed_value_behind_later_valid_one(self):
        call = ToolCall(
            tool_id="offline-example",
            asset="offline.invalid",
            arguments=(("limit", "unapproved"), ("limit", 1)),
        )
        with self.assertRaises((OrchestrationError, ValueError)):
            call.arguments_dict()

    def test_three_occurrences_are_rejected(self):
        call = ToolCall(
            tool_id="offline-example",
            asset="offline.invalid",
            arguments=(("limit", 1), ("dry_run", True), ("limit", 2), ("limit", 3)),
        )
        with self.assertRaises((OrchestrationError, ValueError)):
            call.arguments_dict()

    def test_distinct_arguments_remain_available(self):
        call = ToolCall(
            tool_id="offline-example",
            asset="offline.invalid",
            arguments=(("limit", 1), ("dry_run", True)),
        )
        self.assertEqual(call.arguments_dict(), {"limit": 1, "dry_run": True})


if __name__ == "__main__":
    unittest.main()
