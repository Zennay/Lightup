"""Broken input/output adapters must never promote offline scope review to success."""
from __future__ import annotations

import io
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "review_scope_literal_controls_20261016.py"
VALID = b'{"authorities":["fictional.example.test"]}'


class AdapterFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = runpy.run_path(str(CLI), run_name="offline_adapter_failure")

    def exercise(self, stdin, stdout):
        with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout), \
             patch("socket.socket", side_effect=AssertionError("network forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("process forbidden")), \
             patch("builtins.open", side_effect=AssertionError("file forbidden")):
            return self.module["main"]()

    def test_missing_input_buffer_holds(self):
        sink = io.BytesIO()
        self.assertEqual(self.exercise(SimpleNamespace(), SimpleNamespace(buffer=sink)), 3)
        self.assertEqual(sink.getvalue(), self.module["_HOLD"])

    def test_missing_read_method_holds(self):
        sink = io.BytesIO()
        self.assertEqual(self.exercise(SimpleNamespace(buffer=SimpleNamespace()), SimpleNamespace(buffer=sink)), 3)
        self.assertEqual(sink.getvalue(), self.module["_HOLD"])

    def test_stream_raises_common_adapter_exceptions(self):
        for raised in (ValueError("fictional input leak"), TypeError("fictional input leak"),
                       AttributeError("fictional input leak"), BufferError("fictional input leak")):
            with self.subTest(raised=type(raised).__name__):
                class Reader:
                    def read(self, n):
                        raise raised
                sink = io.BytesIO()
                self.assertEqual(self.exercise(SimpleNamespace(buffer=Reader()), SimpleNamespace(buffer=sink)), 3)
                self.assertEqual(sink.getvalue(), self.module["_HOLD"])
                self.assertNotIn(b"fictional input leak", sink.getvalue())

    def test_missing_output_buffer_never_succeeds(self):
        self.assertEqual(self.exercise(
            SimpleNamespace(buffer=io.BytesIO(VALID)), SimpleNamespace()), 3)

    def test_output_adapter_common_exceptions_never_succeed(self):
        for raised in (ValueError("fictional output leak"), TypeError("fictional output leak"),
                       AttributeError("fictional output leak"), BufferError("fictional output leak")):
            for stage in ("write", "flush"):
                with self.subTest(raised=type(raised).__name__, stage=stage):
                    class Sink:
                        def write(self, data):
                            if stage == "write":
                                raise raised
                            return len(data)
                        def flush(self):
                            if stage == "flush":
                                raise raised
                    self.assertEqual(self.exercise(
                        SimpleNamespace(buffer=io.BytesIO(VALID)),
                        SimpleNamespace(buffer=Sink())), 3)

    def test_closed_streams_hold_no_success(self):
        closed_input = io.BytesIO(VALID)
        closed_input.close()
        output = io.BytesIO()
        self.assertEqual(self.exercise(
            SimpleNamespace(buffer=closed_input), SimpleNamespace(buffer=output)), 3)
        self.assertEqual(output.getvalue(), self.module["_HOLD"])
        closed_output = io.BytesIO()
        closed_output.close()
        self.assertEqual(self.exercise(
            SimpleNamespace(buffer=io.BytesIO(VALID)),
            SimpleNamespace(buffer=closed_output)), 3)


if __name__ == "__main__":
    unittest.main()
