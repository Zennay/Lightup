"""Real CLI acceptance and adversarial segments transport #1505."""
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

from lightup.fictional_review_sequence_segments_cli_1505 import (
    main, parse_fictional_segments,
)

CLI = "lightup.fictional_review_sequence_segments_cli_1505"


def sample():
    def row(i):
        return {
            "case_id": "review-demo.example.test", "sequence": i,
            "packet_sha256": f"{i:064x}",
            "observed_at": f"2026-02-01T10:{i:02d}:00Z",
        }
    return {
        "schema": "fictional_handoff_segments_v1", "expected_records": 6,
        "segments": [
            {"records": [row(5), row(6)]},
            {"records": [row(1), row(2)]},
            {"records": [row(3), row(4)]},
        ],
    }


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def invoke(data, *extra):
    return subprocess.run([sys.executable, "-m", CLI, *extra], input=data,
                          capture_output=True, timeout=15, check=False,
                          env=dict(os.environ, PYTHONPATH="src"))


class TestSegmentsCLI(unittest.TestCase):
    def assert_hold(self, source):
        result = parse_fictional_segments(source)
        self.assertEqual((result.status, result.checked_records), ("HOLD", 0))
        for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(result, field), False)

    def test_valid_segments_real_subprocess_no_authority(self):
        result = invoke(encoded(sample()))
        self.assertEqual(result.returncode, 2, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual((output["status"], output["checked_records"]), ("REVIEW_ONLY", 6))
        for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(output[field], False)
        self.assertNotIn(b"review-demo", result.stdout + result.stderr)

    def test_missing_step_and_overlap_real_process_generic_hold(self):
        for index, replacement in ((0, 4), (1, 4)):
            obj = sample()
            obj["segments"][index]["records"][0]["sequence"] = replacement
            process = invoke(encoded(obj))
            self.assertEqual(process.returncode, 3)
            self.assertEqual(json.loads(process.stdout)["status"], "HOLD")
            self.assertNotIn(b"review-demo", process.stdout + process.stderr)

    def test_corrupted_schema_canonical_field_order_and_duplicate_keys(self):
        good = encoded(sample())
        for changed in (
            good+b"\n", b" "+good,
            good.replace(b'"schema":', b'"schema":"fictional_handoff_segments_v1","schema":', 1),
            good.replace(b'"expected_records":6', b'"expected_records":true', 1),
            good.replace(b'"expected_records":6', b'"expected_records":6.0', 1),
            good.replace(b'"segments"', b'"unknown"', 1),
            good.replace(b'"segments"', b'"SEGMENTS"', 1),
            good.replace(b'review-demo', b'review-\\u0064emo', 1),
            good.replace(b'"records":', b'"records":[],"records":', 1),
            good.replace(b'"sequence":5', b'"sequence":5,"sequence":5', 1),
            good.replace(b'"schema":"fictional_handoff_segments_v1","expected_records":',
                         b'"expected_records":6,"schema":"fictional_handoff_segments_v1","expected_records":', 1),
        ):
            with self.subTest(changed=changed[:90]):
                self.assert_hold(changed)

    def test_invalid_segment_count_total_count_and_empty_records(self):
        for chunks in ([], [{}], [{"records": []}, {"records": []}],
                       [{"records": []}, {"records": [sample()["segments"][0]["records"][0]]}]):
            obj = sample()
            obj["segments"] = chunks
            self.assert_hold(encoded(obj))
        for declared in (0, 1, 5, 7, 17, "6", True, None):
            obj = sample()
            obj["expected_records"] = declared
            self.assert_hold(encoded(obj))

    def test_nonbytes_nonascii_bombs_and_oversize(self):
        for value in (None, "private-token", bytearray(encoded(sample())),
                      b"\xff", b"["*3000+b"]"*3000,
                      b"x"*8193):
            self.assert_hold(value)

    def test_actual_canonical_fixtures(self):
        root = Path(__file__).resolve().parents[1]
        for name, expect, exitcode in (
            ("fictional-segments-1505-valid.json", "REVIEW_ONLY", 2),
            ("fictional-segments-1505-gap.json", "HOLD", 3),
        ):
            out = invoke((root/"docs"/"examples"/name).read_bytes())
            self.assertEqual(out.returncode, exitcode, (name, out.stderr))
            self.assertEqual(json.loads(out.stdout)["status"], expect)

    def test_reject_approve_arg_and_io_faults(self):
        self.assertEqual(invoke(encoded(sample()), "--approve").returncode, 3)
        class BadInput:
            def read(self, _size):
                raise OSError("secret review payload read fault")
        out = io.StringIO()
        with patch("sys.argv", ["segments_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=BadInput())), \
             patch("sys.stdout", out):
            self.assertEqual(main(), 3)
        self.assertEqual(json.loads(out.getvalue())["status"], "HOLD")
        self.assertNotIn("secret", out.getvalue())
        class ClosedOut:
            def write(self, _text):
                raise ValueError("secret review payload write fault")
        with patch("sys.argv", ["segments_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(encoded(sample())))), \
             patch("sys.stdout", ClosedOut()):
            self.assertEqual(main(), 3)

    def test_split_pipe_eof_and_trailing_data(self):
        inp = encoded(sample())
        for trailer, status, exitcode in ((b"", "REVIEW_ONLY", 2), (b"x", "HOLD", 3)):
            p = subprocess.Popen([sys.executable, "-m", CLI], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=dict(os.environ, PYTHONPATH="src"))
            try:
                p.stdin.write(inp[:9])
                p.stdin.flush()
                p.stdin.write(inp[9:31])
                p.stdin.flush()
                stdout, stderr = p.communicate(inp[31:]+trailer, timeout=15)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()
            self.assertEqual(p.returncode, exitcode, stderr)
            self.assertEqual(json.loads(stdout)["status"], status)


if __name__ == "__main__":
    unittest.main()
