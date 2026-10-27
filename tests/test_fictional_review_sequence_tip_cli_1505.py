"""Real-process canonical fictional tip envelope tests (#1505)."""
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

from lightup.fictional_review_sequence_tip_cli_1505 import main, parse_fictional_tip

MODULE = "lightup.fictional_review_sequence_tip_cli_1505"
EXAMPLES = Path(__file__).resolve().parents[1] / "docs" / "examples"


def sample(n=3):
    return {
        "schema": "fictional_handoff_tip_v1",
        "expected_tip_sha256": f"{n:064x}",
        "records": [
            {"case_id": "review-demo.example.test",
             "sequence": i, "packet_sha256": f"{i:064x}",
             "observed_at": f"2026-01-01T12:{i:02d}:00Z",
             "previous_packet_sha256": f"{i-1:064x}"}
            for i in range(1, n+1)
        ],
    }


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def invoke(raw, *args):
    return subprocess.run([sys.executable, "-m", MODULE, *args],
                          input=raw, capture_output=True, check=False,
                          env=dict(os.environ, PYTHONPATH="src"), timeout=15)


class TestSyntheticTipCLI(unittest.TestCase):
    def assert_hold(self, data):
        r = parse_fictional_tip(data)
        self.assertEqual((r.status, r.checked_records), ("HOLD", 0))
        for field in ("authorized", "consent_verified",
                      "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(r, field), False)

    def test_valid_actual_subprocess_remains_no_authority(self):
        for count in (2, 3, 16):
            p = invoke(encode(sample(count)))
            self.assertEqual(p.returncode, 2, p.stderr)
            value = json.loads(p.stdout)
            self.assertEqual((value["status"], value["checked_records"]),
                             ("REVIEW_ONLY", count))
            for field in ("authorized", "consent_verified",
                          "dispatch_allowed", "release_allowed"):
                self.assertIs(value[field], False)
            self.assertNotIn(b"review-demo", p.stdout+p.stderr)

    def test_changed_terminal_hint_or_link_broken_is_hold(self):
        original = sample()
        for field, replacement in (
            ("expected_tip_sha256", "f"*64),
            ("expected_tip_sha256", "A"*64),
            ("expected_tip_sha256", "f"*63),
        ):
            doc = sample()
            doc[field] = replacement
            self.assert_hold(encode(doc))
        doc = sample()
        doc["records"][-1]["packet_sha256"] = "f"*64
        self.assert_hold(encode(doc))
        doc["expected_tip_sha256"] = "f"*64
        self.assertEqual(parse_fictional_tip(encode(doc)).status, "REVIEW_ONLY")
        doc["records"][1]["previous_packet_sha256"] = "f"*64
        self.assert_hold(encode(doc))

    def test_committed_real_fixtures(self):
        for name, expected, code in (
            ("fictional-tip-1505-valid.json", "REVIEW_ONLY", 2),
            ("fictional-tip-1505-divergent.json", "HOLD", 3),
        ):
            proc = invoke((EXAMPLES/name).read_bytes())
            self.assertEqual(proc.returncode, code, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["status"], expected)

    def test_duplicate_unknown_reordered_escaped_and_noncanonical(self):
        original = encode(sample())
        for bad in (
            b" "+original, original+b"\n", original+b"{}",
            original.replace(b'"schema":', b'"schema":"fictional_handoff_tip_v1","schema":', 1),
            original.replace(b'"expected_tip_sha256"', b'"unexpected"', 1),
            original.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1),
            original.replace(b"review-demo", b"review-\\u0064emo", 1),
            original.replace(b'"schema":"fictional_handoff_tip_v1","expected_tip_sha256"',
                             b'"expected_tip_sha256":"f","schema":"fictional_handoff_tip_v1","expected_tip_sha256"', 1),
        ):
            self.assert_hold(bad)

    def test_nonbytes_unicode_and_input_limit(self):
        for bad in (None, "token", bytearray(encode(sample())), b"",
                    b"\xff", b"x"*8193, b"["+b"["*5000+b"]"*5000,
                    encode(sample()).replace(b"review-demo", b"review-\\ud800")):
            self.assert_hold(bad)

    def test_no_arg_approval_and_broken_streams(self):
        self.assertEqual(invoke(encode(sample()), "--approve").returncode, 3)
        class Reader:
            def read(self, _n):
                raise OSError("private review data")
        out = io.StringIO()
        with patch("sys.argv", ["tip_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=Reader())), \
             patch("sys.stdout", out):
            self.assertEqual(main(), 3)
        self.assertEqual(json.loads(out.getvalue())["status"], "HOLD")
        self.assertNotIn("private", out.getvalue())
        class Output:
            def write(self, _data):
                raise ValueError("private closed stream")
        with patch("sys.argv", ["tip_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(encode(sample())))), \
             patch("sys.stdout", Output()):
            self.assertEqual(main(), 3)

    def test_real_split_pipe_and_extra_trailer(self):
        raw = encode(sample())
        for extra, status, code in ((b"", "REVIEW_ONLY", 2), (b"x", "HOLD", 3)):
            p = subprocess.Popen([sys.executable, "-m", MODULE],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 env=dict(os.environ, PYTHONPATH="src"))
            try:
                p.stdin.write(raw[:11])
                p.stdin.flush()
                p.stdin.write(raw[11:33])
                p.stdin.flush()
                out, err = p.communicate(raw[33:] + extra, timeout=15)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()
            self.assertEqual(p.returncode, code, err)
            self.assertEqual(json.loads(out)["status"], status)

    def test_jointly_modified_terminal_and_all_parent_hints_not_consent(self):
        obj = sample()
        for row in obj["records"]:
            index = row["sequence"]
            row["packet_sha256"] = f"{8000+index:064x}"
            row["previous_packet_sha256"] = "0"*64 if index==1 else f"{8000+index-1:064x}"
        obj["expected_tip_sha256"] = f"{8003:064x}"
        outcome = parse_fictional_tip(encode(obj))
        self.assertEqual(outcome.status, "REVIEW_ONLY")
        for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(outcome, field), False)


if __name__ == "__main__":
    unittest.main()
