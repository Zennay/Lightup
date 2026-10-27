"""Fail-closed Unicode path identity for offline LightUp scope work ownership."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from scope_issue_ownership_audit_20261015 import InvalidSnapshot, audit


def snapshot(path: str) -> bytes:
    return json.dumps({
        "issues": [{"number": 1, "open": True, "lane": "scope-authorization"}],
        "prs": [{"number": 2, "open": True, "draft": True,
                 "issues": [1], "paths": [path]}]
    }).encode()


class UnicodeOwnershipPathTests(unittest.TestCase):
    def test_ascii_baseline(self):
        self.assertEqual(audit(snapshot("src/lightup/scope.py"))["status"], "HOLD")

    def test_visible_nfc_unicode_can_be_reviewed(self):
        result = audit(snapshot("docs/caf\u00e9.md"))
        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["can_merge"])

    def test_decomposed_nfd_file_denied(self):
        with self.assertRaises(InvalidSnapshot):
            audit(snapshot("docs/cafe\u0301.md"))

    def test_bidirectional_override_denied(self):
        for value in ("tests/abc\u202e.py", "tests/a\u202c.py",
                      "tests/\u202afolder.py", "tests/\u2067name.py",
                      "tests/\u2069name.py", "tests/\u200efoo.py"):
            with self.subTest(value=value), self.assertRaises(InvalidSnapshot):
                audit(snapshot(value))

    def test_zero_width_joiner_denied(self):
        for char in ("\u200d", "\u200c", "\ufeff"):
            with self.subTest(char=ord(char)), self.assertRaises(InvalidSnapshot):
                audit(snapshot("docs/a" + char + "b.md"))

    def test_c0_control_denied(self):
        for ch in ("\x01", "\x1f", "\x7f", "\t"):
            with self.subTest(number=ord(ch)), self.assertRaises(InvalidSnapshot):
                audit(snapshot("tests/a" + ch + ".py"))

    def test_surrogate_denied_even_when_escaped(self):
        with self.assertRaises(InvalidSnapshot):
            audit(snapshot("docs/\ud800.py"))

    def test_hidden_bidi_cannot_hide_an_exact_path_collision(self):
        base = {"issues": [{"number": 1, "open": True, "lane": "scope-authorization"}],
                "prs": [
                    {"number": 2, "open": True, "draft": True,
                     "issues": [1], "paths": ["tests/scope.py"]},
                    {"number": 3, "open": True, "draft": True,
                     "issues": [1], "paths": ["tests/sco\u202epe.py"]}
                ]}
        with self.assertRaises(InvalidSnapshot):
            audit(json.dumps(base).encode())


if __name__ == "__main__":
    unittest.main()
