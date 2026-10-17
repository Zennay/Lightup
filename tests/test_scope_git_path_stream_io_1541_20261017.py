"""Fail-closed stdout and stdin transport acceptance for synthetic #1541 CLI.

All I/O objects are local fakes. No Git, socket, filesystem, real targets
or production authorization are invoked by the reviewed function.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import review_scope_git_path_streams_synthetic_1541 as cli


def packet():
    return json.dumps({
        "schema": "lightup.scope_git_paths_synthetic.v1",
        "synthetic_only": True,
        "status_b64": base64.b64encode(b"M\0safe.py\0").decode("ascii"),
        "numstat_b64": base64.b64encode(b"1\t1\tsafe.py\0").decode("ascii"),
    }, sort_keys=True, separators=(",", ":")).encode("ascii")


class _FakeInput:
    def __init__(self, data=None, error=None):
        self.buffer = self
        self.data = data
        self.error = error

    def read(self, limit):
        if self.error is not None:
            raise self.error
        return self.data


class _FakeOutput:
    def __init__(self, behavior="complete"):
        self.buffer = self
        self.behavior = behavior
        self.written = b""
        self.flushed = False

    def write(self, data):
        self.written = data
        if isinstance(self.behavior, Exception):
            raise self.behavior
        if self.behavior == "complete":
            return len(data)
        if self.behavior == "short":
            return len(data) - 1
        if self.behavior == "long":
            return len(data) + 1
        if self.behavior == "true":
            return True
        if self.behavior == "none":
            return None
        return 0

    def flush(self):
        self.flushed = True


class SyntheticStreamTransportTests(unittest.TestCase):
    def execute(self, input_value=None, *, input_error=None,
                output_behavior="complete", arguments=("script.py",)):
        fake_out = _FakeOutput(output_behavior)
        fake_in = _FakeInput(input_value, input_error)
        with patch.object(sys, "stdin", fake_in), patch.object(sys, "stdout", fake_out), \
                patch.object(sys, "argv", list(arguments)):
            result = cli.main()
        return result, fake_out

    def test_complete_canonical_receipt_review_only_three(self):
        code, output = self.execute(packet())
        self.assertEqual(code, 3)
        self.assertTrue(output.flushed)
        self.assertEqual(json.loads(output.written)["status"], "REVIEW_ONLY")

    def test_error_while_reading_stdin_is_generic_hold(self):
        code, output = self.execute(input_error=OSError("SYNTHETIC_INPUT_SECRET"))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.written)["status"], "HOLD")
        self.assertNotIn(b"SYNTHETIC_INPUT_SECRET", output.written)

    def test_error_while_writing_stdout_is_not_success(self):
        code, _ = self.execute(packet(), output_behavior=BrokenPipeError("closed"))
        self.assertEqual(code, 2)

    def test_partial_stdout_write_cannot_report_success_exit(self):
        code, output = self.execute(packet(), output_behavior="short")
        self.assertEqual(code, 2)
        self.assertIs(output.flushed, False)

    def test_overreported_stdout_write_cannot_report_success_exit(self):
        code, output = self.execute(packet(), output_behavior="long")
        self.assertEqual(code, 2)
        self.assertIs(output.flushed, False)

    def test_noninteger_stdout_write_acknowledgements_hold(self):
        for shape in ("true", "none", "zero"):
            with self.subTest(shape=shape):
                code, output = self.execute(packet(), output_behavior=shape)
                self.assertEqual(code, 2)
                self.assertIs(output.flushed, False)

    def test_extra_cli_arguments_are_held_with_no_echo(self):
        code, output = self.execute(packet(),
                                    arguments=("script.py", "--grant=SECRET_NEVER_ECHO"))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.written)["status"], "HOLD")
        self.assertNotIn(b"SECRET_NEVER_ECHO", output.written)

    def test_invalid_content_does_not_inherit_previous_success(self):
        self.assertEqual(self.execute(packet())[0], 3)
        code, output = self.execute(b"invalid")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.written)["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
