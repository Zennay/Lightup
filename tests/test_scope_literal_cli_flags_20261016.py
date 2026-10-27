"""No command-line switches can imply authorization or be silently ignored."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts/review_scope_literal_controls_20261016.py"
VALID = b'{"authorities":["fictional.example.test"]}'


class StrictCliArgvTests(unittest.TestCase):
    def invoke(self, *args: str, packet: bytes = VALID):
        return subprocess.run(
            [sys.executable, str(CLI), *args], input=packet,
            capture_output=True, check=False, timeout=10, cwd=ROOT,
        )

    def test_no_options_only_review(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "REVIEW_ONLY")
        self.assertTrue(all(value is False for key, value in json.loads(result.stdout).items() if key != "status"))

    def test_unknown_flags_hold_without_echo(self):
        cases = (
            ("--authorize",), ("--grant=true",), ("--mode", "authorized"),
            ("--target", "fictional.example.test"), ("--help",),
            ("--version",), ("--",), ("fictional.example.test",),
            ("-h",), ("--consent", "yes"), ("--dispatch",),
        )
        for flags in cases:
            with self.subTest(flags=flags):
                result = self.invoke(*flags)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(json.loads(result.stdout)["status"], "HOLD")
                self.assertTrue(all(value is False for key, value in json.loads(result.stdout).items() if key != "status"))
                self.assertNotIn(b"fictional.example.test", result.stdout)
                self.assertEqual(result.stderr, b"")

    def test_input_controls_keep_hold_with_or_without_flag(self):
        for flags in ((), ("--authorize",)):
            with self.subTest(flags=flags):
                result = self.invoke(*flags, packet=b'{"authorities":["local%0ahost"]}')
                self.assertEqual(result.returncode, 3)
                self.assertEqual(json.loads(result.stdout)["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
