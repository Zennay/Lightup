"""Offline reference contract for safely rendering denied scope identifiers.

This is NOT a production implementation, audit event, or source of authority.
"""
from __future__ import annotations

import json
import unittest


def safe_denial_label(value: object, *, limit: int = 96) -> str:
    """Reference only: bounded, single-line, non-reversible untrusted label."""
    if type(value) is not str:
        return "<invalid>"
    output = []
    for char in value:
        code = ord(char)
        if code < 0x20 or 0x7F <= code <= 0x9F or char in ("\\", "\u2028", "\u2029"):
            output.append("?")
        else:
            output.append(char)
        if len(output) >= limit:
            break
    return "".join(output)


def reference_denial_record(target: object, reason: object) -> dict[str, str]:
    """Keep metadata data-only; no raw target interpolation into log templates."""
    return {"event": "scope_denied", "target_label": safe_denial_label(target),
            "reason_label": safe_denial_label(reason, limit=32)}


class DenialLogSanitizationContract(unittest.TestCase):
    def test_crlf_and_tab_cannot_forge_another_line(self):
        record = reference_denial_record("host.example\r\nALLOW admin\t", "denied\naccepted")
        self.assertNotIn("\n", json.dumps(record))
        self.assertNotIn("\r", record["target_label"])
        self.assertNotIn("\t", record["target_label"])
        self.assertNotIn("ALLOW admin", record["target_label"].splitlines()[-1] if len(record["target_label"].splitlines()) > 1 else "")

    def test_unicode_line_and_control_separators(self):
        record = reference_denial_record("alpha\u2028beta\u2029gamma\x1b[31m\x85", "out_of_scope")
        self.assertNotIn("\u2028", record["target_label"])
        self.assertNotIn("\u2029", record["target_label"])
        self.assertNotIn("\x1b", record["target_label"])
        self.assertNotIn("\x85", record["target_label"])

    def test_non_string_objects_never_execute_string_conversion(self):
        class Hostile:
            def __str__(self):
                raise AssertionError("untrusted object stringified")
        record = reference_denial_record(Hostile(), Hostile())
        self.assertEqual(record["target_label"], "<invalid>")
        self.assertEqual(record["reason_label"], "<invalid>")

    def test_bounded_large_input_and_reason(self):
        record = reference_denial_record("x" * 100000, "y" * 100000)
        self.assertEqual(len(record["target_label"]), 96)
        self.assertEqual(len(record["reason_label"]), 32)

    def test_structured_serialization_does_not_interpolate_keys(self):
        record = reference_denial_record('"},"event":"scope_allowed","x":"', "out_of_scope")
        self.assertEqual(record["event"], "scope_denied")
        self.assertEqual(json.loads(json.dumps(record)), record)

    def test_original_values_are_not_modified(self):
        value = "bad\r\nvalue"
        reference_denial_record(value, "out_of_scope")
        self.assertEqual(value, "bad\r\nvalue")


if __name__ == "__main__":
    unittest.main()
