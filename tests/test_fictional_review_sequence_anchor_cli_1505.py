"""Actual-process acceptance of fictional anchor-vs-segments stdin CLI #1505."""
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

from lightup.fictional_review_sequence_anchor_cli_1505 import (
    main, parse_fictional_anchor,
)
from lightup.fictional_review_sequence_cli_1505 import emit_review

CLI = "lightup.fictional_review_sequence_anchor_cli_1505"
ROOT = Path(__file__).resolve().parents[1]


def specimen():
    def row(i):
        return {"case_id":"review-demo.example.test","sequence":i,
                "packet_sha256":f"{i:064x}",
                "observed_at":f"2026-02-01T10:{i:02d}:00Z"}
    return {
        "schema": "fictional_handoff_anchor_v1", "expected_records": 6,
        "segments": [
            {"records": [row(5), row(6)]},
            {"records": [row(1), row(2)]},
            {"records": [row(3), row(4)]},
        ],
        "capture": {"records": [row(i) for i in range(1, 7)]},
    }


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def invoke(blob, *args):
    return subprocess.run([sys.executable, "-m", CLI, *args], input=blob,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=dict(os.environ, PYTHONPATH="src"), timeout=15, check=False)


class TestAnchorCLI(unittest.TestCase):
    def assert_hold(self, blob):
        status = parse_fictional_anchor(blob)
        self.assertEqual((status.status, status.checked_records), ("HOLD", 0))
        self.assertNotIn("example.test", emit_review(status))
        for k in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(status, k), False)

    def test_valid_real_cli_never_gives_execution_authority(self):
        p = invoke(encoded(specimen()))
        self.assertEqual(p.returncode, 2, p.stderr)
        outcome = json.loads(p.stdout)
        self.assertEqual((outcome["status"], outcome["checked_records"]), ("REVIEW_ONLY", 6))
        for k in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(outcome[k], False)
        self.assertNotIn(b"review-demo", p.stdout + p.stderr)

    def test_different_but_individually_valid_baseline_is_hold(self):
        base = specimen()
        for field, replacement in (
            ("observed_at", "2026-02-01T10:03:30Z"),
            ("packet_sha256", "f"*64),
            ("case_id", "review-other.example.test"),
        ):
            changed = json.loads(json.dumps(base))
            changed["capture"]["records"][2][field] = replacement
            p = invoke(encoded(changed))
            self.assertEqual(p.returncode, 3)
            self.assertEqual(json.loads(p.stdout)["status"], "HOLD")
            self.assertNotIn(b"review-demo", p.stdout + p.stderr)

    def test_nonauthorizing_even_if_both_copies_are_jointly_fabricated(self):
        src = specimen()
        for group in (*src["segments"], src["capture"]):
            for record in group["records"]:
                record["packet_sha256"] = f"{record['sequence']+1024:064x}"
        value = json.loads(invoke(encoded(src)).stdout)
        self.assertEqual(value["status"], "REVIEW_ONLY")
        for k in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(value[k], False)

    def test_invalid_json_and_duplicate_keys_are_hold(self):
        good = encoded(specimen())
        for blob in (
            b" "+good, good+b"\n", good+b"{}", good.replace(b"review-demo", b"review-\\u0064emo", 1),
            good.replace(b'"schema":', b'"schema":"fictional_handoff_anchor_v1","schema":', 1),
            good.replace(b'"capture":', b'"capture":{},"capture":', 1),
            good.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1),
            good.replace(b'"capture"', b'"CAPTURE"', 1),
            good.replace(b'"expected_records":6', b'"expected_records":true', 1),
            good.replace(b'"expected_records":6', b'"expected_records":6.0', 1),
            good.replace(b'"records":', b'"records":[],"records":', 1),
            good.replace(b'"schema":"fictional_handoff_anchor_v1","expected_records"',
                         b'"expected_records":6,"schema":"fictional_handoff_anchor_v1","expected_records"', 1),
        ):
            with self.subTest(bad=blob[:70]):
                self.assert_hold(blob)

    def test_wrong_capture_lengths_and_container_shapes(self):
        src = specimen()
        for change in (
            {"records":[]}, {"records":src["capture"]["records"][:5]},
            {"records":src["capture"]["records"] + src["capture"]["records"][:1]},
            {"not_records":src["capture"]["records"]}, [], None, "faked",
        ):
            modified = json.loads(json.dumps(src))
            modified["capture"] = change
            self.assert_hold(encoded(modified))
        for count in (True, 6.0, "6", None, 0, 17):
            modified = json.loads(json.dumps(src))
            modified["expected_records"] = count
            self.assert_hold(encoded(modified))

    def test_nonbytes_nested_bombs_oversize_and_escaped_unicode(self):
        for blob in (None, "secret-raw-data", bytearray(encoded(specimen())),
                     b"x"*8193, b"["+b"["*4000+b"]"*4000, b"\xff",
                     encoded(specimen()).replace(b"review-demo", b"review-\\ud800"),
                     encoded(specimen()).replace(b"review-demo", b"review-\\u202e")):
            self.assert_hold(blob)

    def test_real_canonical_positive_and_mismatch_example_files(self):
        for name, expected_status, code in (
            ("fictional-anchor-1505-valid.json", "REVIEW_ONLY", 2),
            ("fictional-anchor-1505-drift.json", "HOLD", 3),
        ):
            data = (ROOT / "docs" / "examples" / name).read_bytes()
            p = invoke(data)
            self.assertEqual(p.returncode, code, (name, p.stderr))
            self.assertEqual(json.loads(p.stdout)["status"], expected_status)

    def test_real_split_pipe_extra_bytes_and_disallowed_options(self):
        blob = encoded(specimen())
        for trailer, status, code in ((b"", "REVIEW_ONLY", 2), (b"x", "HOLD", 3)):
            p = subprocess.Popen([sys.executable, "-m", CLI], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=dict(os.environ, PYTHONPATH="src"))
            try:
                p.stdin.write(blob[:13])
                p.stdin.flush()
                p.stdin.write(blob[13:91])
                p.stdin.flush()
                out, err = p.communicate(blob[91:]+trailer, timeout=15)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()
            self.assertEqual(p.returncode, code, err)
            self.assertEqual(json.loads(out)["status"], status)
        self.assertEqual(invoke(blob, "--approve").returncode, 3)

    def test_broken_input_and_output_streams_are_generic_hold(self):
        class Reader:
            def read(self, _size):
                raise OSError("confidential source data")
        out = io.StringIO()
        with patch("sys.argv", ["anchor_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=Reader())), \
             patch("sys.stdout", out):
            self.assertEqual(main(), 3)
        self.assertEqual(json.loads(out.getvalue())["status"], "HOLD")
        self.assertNotIn("confidential", out.getvalue())
        class BrokenWriter:
            def write(self, _text):
                raise ValueError("confidential closed output")
        with patch("sys.argv", ["anchor_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(encoded(specimen())))), \
             patch("sys.stdout", BrokenWriter()):
            self.assertEqual(main(), 3)


if __name__ == "__main__":
    unittest.main()
