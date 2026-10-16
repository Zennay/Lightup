"""Isolated real-process tests for two-capture fictional CLI (#1505)."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from lightup.fictional_review_sequence_pair_cli_1505 import (
    main, parse_fictional_pair,
)
from lightup.fictional_review_sequence_cli_1505 import emit_review

CLI = "lightup.fictional_review_sequence_pair_cli_1505"


def sample():
    record = lambda n: {
        "case_id": "review-demo.example.test", "sequence": n,
        "packet_sha256": f"{n:064x}", "observed_at": f"2026-02-01T10:{n:02d}:00Z"
    }
    capture = {"schema": "fictional_handoff_sequence_v1",
               "records": [record(i) for i in (1, 2, 3)]}
    return {"schema": "fictional_handoff_pair_v1",
            "capture_a": capture,
            "capture_b": json.loads(json.dumps(capture))}


def encode(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def invoke(payload, *extra):
    return subprocess.run([sys.executable, "-m", CLI, *extra], input=payload,
                          capture_output=True, env=dict(os.environ, PYTHONPATH="src"),
                          timeout=15, check=False)


class TestFictionalPairCLI(unittest.TestCase):
    def assert_hold(self, data):
        outcome = parse_fictional_pair(data)
        self.assertEqual((outcome.status, outcome.checked_records), ("HOLD", 0))
        self.assertNotIn("example.test", emit_review(outcome))
        for f in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(outcome, f), False)

    def test_matching_copies_real_process_review_only_and_four_false(self):
        process = invoke(encode(sample()))
        self.assertEqual(process.returncode, 2, process.stderr)
        value = json.loads(process.stdout)
        self.assertEqual((value["status"], value["checked_records"]), ("REVIEW_ONLY", 3))
        for f in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(value[f], False)
        self.assertNotIn(b"review-demo", process.stdout)

    def test_changed_but_individually_valid_timestamp_hold(self):
        payload = sample()
        payload["capture_b"]["records"][1]["observed_at"] = "2026-02-01T10:02:10Z"
        process = invoke(encode(payload))
        self.assertEqual(process.returncode, 3)
        self.assertEqual(json.loads(process.stdout)["status"], "HOLD")
        self.assertNotIn(b"review-demo", process.stdout + process.stderr)

    def test_two_matching_but_invalid_copies_never_review(self):
        obj = sample()
        for case in ("review-evil.com", "REVIEW-demo.example.test", "review-é.example.test"):
            import copy
            mutated = copy.deepcopy(obj)
            for key in ("capture_a", "capture_b"):
                for record in mutated[key]["records"]:
                    record["case_id"] = case
            self.assert_hold(encode(mutated))

    def test_partial_reordered_missing_duplicate_and_noncanonical(self):
        good = encode(sample())
        for data in (
            good+b" ", b" "+good, good+b"{}", good.replace(b"review-demo", b"review-\\u0064emo"),
            good.replace(b'"schema":', b'"schema":"fictional_handoff_pair_v1","schema":', 1),
            good.replace(b'"capture_a":', b'"capture_b":{},"capture_a":', 1),
            good.replace(b'"capture_a"', b'"unexpected"', 1),
            good.replace(b'"capture_a"', b'"capture_b"', 1),
            good.replace(b'"packet_sha256"', b'"packet_sha256","unknown"', 1),
            good.replace(b'"sequence":2', b'"sequence":3', 1),
            good.replace(b'"capture_a":', b'"capture_a":null,"capture_a":', 1),
        ):
            self.assert_hold(data)

    def test_nonascii_nonbytes_oversize_and_nested_bombs(self):
        for payload in (None, "secret-token", bytearray(encode(sample())),
                        b"\xff", b"["+b"["*5000+b"]"*5000, b"x"*8193):
            self.assert_hold(payload)

    def test_actual_fixture_files_and_exit_codes(self):
        root = Path(__file__).resolve().parents[1]
        for filename, status, exitcode in (
            ("fictional-pair-1505-matching.json", "REVIEW_ONLY", 2),
            ("fictional-pair-1505-divergent.json", "HOLD", 3),
        ):
            p = root / "docs" / "examples" / filename
            process = invoke(p.read_bytes())
            self.assertEqual(process.returncode, exitcode, (filename, process.stderr))
            self.assertEqual(json.loads(process.stdout)["status"], status)

    def test_unknown_cli_args_and_io_errors_fail_closed(self):
        self.assertEqual(invoke(encode(sample()), "--approve").returncode, 3)
        class BadReader:
            def read(self, _n):
                raise OSError("confidential aborted input")
        output = io.StringIO()
        with patch("sys.argv", ["pair_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=BadReader())), \
             patch("sys.stdout", output):
            self.assertEqual(main(), 3)
        self.assertNotIn("confidential", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")

    def test_fragmented_pair_stdin_pipe_and_trailer(self):
        payload = encode(sample())
        for trailer, expected_status, expected_exit in (
            (b"", "REVIEW_ONLY", 2), (b"x", "HOLD", 3)
        ):
            process = subprocess.Popen(
                [sys.executable, "-m", CLI], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=dict(os.environ, PYTHONPATH="src")
            )
            try:
                process.stdin.write(payload[:13])
                process.stdin.flush()
                process.stdin.write(payload[13:50])
                process.stdin.flush()
                out, err = process.communicate(payload[50:] + trailer, timeout=15)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            self.assertEqual(process.returncode, expected_exit, err)
            self.assertEqual(json.loads(out)["status"], expected_status)



    def test_invalid_input_handle_and_output_failures_never_return_success(self):
        output = io.StringIO()
        with patch("sys.argv", ["pair_cli"]), \
             patch("sys.stdin", object()), \
             patch("sys.stdout", output):
            self.assertEqual(main(), 3)
        self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")

        class ClosedOutput:
            def write(self, _value):
                raise ValueError("confidential closed stdout")

        with patch("sys.argv", ["pair_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(encode(sample())))), \
             patch("sys.stdout", ClosedOutput()):
            self.assertEqual(main(), 3)

        class BrokenFlush:
            def write(self, text):
                return len(text)
            def flush(self):
                raise OSError("confidential write failed")

        with patch("sys.argv", ["pair_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(encode(sample())))), \
             patch("sys.stdout", BrokenFlush()):
            self.assertEqual(main(), 3)

if __name__ == "__main__":
    unittest.main()
