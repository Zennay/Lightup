"""#1424: direct CLI trust boundaries for untrusted argv and output sinks.

No actual target operations: in-memory synthetic-only, non-authorizing CLIs.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import TestCase, main, mock

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts"))

from review_scope_lab_literal_1424_offline import main as literal_main
from review_scope_lab_batch_1424_offline import main as batch_main


_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)


class OutputSinkFailClosedTests(TestCase):
    def test_single_cli_exact_flag_identity_before_untrusted_hooks(self):
        class AggressiveStr(str):
            def __eq__(self, _other):
                raise AssertionError("malicious flag equality evaluated")

        class AggressiveList(list):
            def __len__(self):
                raise AssertionError("malicious argv length evaluated")

        class Spoof:
            def __eq__(self, _other):
                raise AssertionError("malicious flag eq evaluated")

        attempts = (
            [AggressiveStr("--literal"), "10.0.0.1"],
            [Spoof(), "10.0.0.1"],
            ["--literal", AggressiveStr("10.0.0.1")],
            AggressiveList(["--literal", "10.0.0.1"]),
            ("--literal", "10.0.0.1"),
            [None, "10.0.0.1"],
            ["--literal", True],
        )
        for argv in attempts:
            with self.subTest(type=type(argv).__name__):
                output, errors = io.StringIO(), io.StringIO()
                with mock.patch.object(sys, "stdout", output), mock.patch.object(sys, "stderr", errors):
                    code = literal_main(argv)
                self.assertEqual(code, 2)
                self.assertEqual(errors.getvalue(), "")
                receipt = json.loads(output.getvalue())
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["classification"], "UNTRUSTED")
                for flag in _FLAGS:
                    self.assertIs(receipt[flag], False)

        output = io.StringIO()
        with mock.patch.object(sys, "stdout", output):
            code = literal_main(["--literal", "10.0.0.1"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["status"], "REVIEW_ONLY")

    def test_both_clis_handle_nonwritable_output_with_nonzero_hold(self):
        class BrokenOutput:
            def __init__(self, fault):
                self.fault = fault
                self.calls = 0

            def write(self, _message):
                self.calls += 1
                raise self.fault

        for fault in (
            BrokenPipeError("synthetic-private-pipe-path"),
            OSError("synthetic-private-write-error"),
            UnicodeEncodeError("ascii", "π", 0, 1, "synthetic-secret-encoding"),
        ):
            for mode, main_func, args, stdin in (
                ("single-positive", literal_main, ["--literal", "10.0.0.1"], None),
                ("single-negative", literal_main, ["--literal", "192.0.2.1"], None),
                ("batch-positive", batch_main, ["--stdin-json"], b'{"literals":["10.0.0.1"]}'),
                ("batch-negative", batch_main, ["--stdin-json"], b'{"literals":["10.0.0.1","192.0.2.1"]}'),
            ):
                with self.subTest(mode=mode, fault=type(fault).__name__):
                    output = BrokenOutput(fault)
                    errors = io.StringIO()
                    input_stream = SimpleNamespace(buffer=io.BytesIO(stdin or b""))
                    with (
                        mock.patch.object(sys, "stdout", output),
                        mock.patch.object(sys, "stderr", errors),
                        mock.patch.object(sys, "stdin", input_stream),
                    ):
                        code = main_func(args)
                    self.assertEqual(code, 2)
                    self.assertEqual(output.calls, 1)
                    self.assertEqual(errors.getvalue(), "")

    def test_nonfailing_sink_keeps_privacy_and_non_authority(self):
        for main_func, args, stdin, status, code in (
            (literal_main, ["--literal", "127.0.0.1"], None, "REVIEW_ONLY", 3),
            (literal_main, ["--literal", "192.0.2.1"], None, "HOLD", 2),
            (batch_main, ["--stdin-json"], b'{"literals":["127.0.0.1"]}', "REVIEW_ONLY", 3),
            (batch_main, ["--stdin-json"], b'{"literals":["127.0.0.1","192.0.2.1"]}', "HOLD", 2),
        ):
            with self.subTest(main=main_func.__module__, status=status):
                output, errors = io.StringIO(), io.StringIO()
                input_stream = SimpleNamespace(buffer=io.BytesIO(stdin or b""))
                with (
                    mock.patch.object(sys, "stdout", output),
                    mock.patch.object(sys, "stderr", errors),
                    mock.patch.object(sys, "stdin", input_stream),
                ):
                    actual = main_func(args)
                self.assertEqual(actual, code)
                self.assertEqual(errors.getvalue(), "")
                record = json.loads(output.getvalue())
                self.assertEqual(record["status"], status)
                self.assertNotIn("127.0.0.1", output.getvalue())
                self.assertNotIn("192.0.2.1", output.getvalue())
                for flag in _FLAGS:
                    self.assertIs(record[flag], False)


if __name__ == "__main__":
    main()
