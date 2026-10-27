"""Fail-closed output errors for fictitious scope review CLI.

A partial or failed stream write must never return the review-only exit code.
"""
from __future__ import annotations

import io
from pathlib import Path
import runpy
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts/review_scope_literal_controls_20261016.py"
VALID = b'{"authorities":["fictional.example.test"]}'
INVALID = b'{"authorities":["local%0ahost"]}'


class OutputFramingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = runpy.run_path(str(CLI), run_name="offline_output_framing_tests")

    def invoke(self, input_bytes, stdout_buffer):
        with patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(input_bytes))), \
             patch.object(sys, "stdout", SimpleNamespace(buffer=stdout_buffer)), \
             patch("socket.socket", side_effect=AssertionError("no network")), \
             patch("subprocess.Popen", side_effect=AssertionError("no subprocess")), \
             patch("builtins.open", side_effect=AssertionError("no file I/O")):
            return self.module["main"]()

    def test_broken_pipe_yields_non_success_without_retry(self):
        for payload in (VALID, INVALID):
            with self.subTest(payload=payload):
                class Stream:
                    writes = 0
                    def write(self, data):
                        self.writes += 1
                        raise BrokenPipeError("fictional sink detail must not leak")
                stream = Stream()
                self.assertEqual(self.invoke(payload, stream), 3)
                self.assertEqual(stream.writes, 1)

    def test_short_write_does_not_report_review_only(self):
        for written in (0, 1, None, True):
            with self.subTest(written=written):
                class Stream:
                    def write(self, data):
                        return written
                    def flush(self):
                        pass
                self.assertEqual(self.invoke(VALID, Stream()), 3)

    def test_failed_flush_does_not_report_review_only(self):
        class Stream:
            def write(self, data):
                return len(data)
            def flush(self):
                raise OSError("fictional sink detail")
        self.assertEqual(self.invoke(VALID, Stream()), 3)

    def test_complete_output_has_exact_status_and_return_code(self):
        for data, expected_status, expected_code in (
            (VALID, self.module["_REVIEW"], 2),
            (INVALID, self.module["_HOLD"], 3),
        ):
            with self.subTest(data=data):
                stream = io.BytesIO()
                self.assertEqual(self.invoke(data, stream), expected_code)
                self.assertEqual(stream.getvalue(), expected_status)
                self.assertNotIn(b"fictional.example.test", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
