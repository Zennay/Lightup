"""Canonical JSON and genuine subprocess acceptance of fake parent links #1505."""
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

from lightup.fictional_review_sequence_cli_1505 import emit_review
from lightup.fictional_review_sequence_linked_cli_1505 import main, parse_fictional_links


MODULE = "lightup.fictional_review_sequence_linked_cli_1505"
DOCS = Path(__file__).resolve().parents[1] / "docs" / "examples"


def source(count=3):
    return {"schema": "fictional_handoff_links_v1", "records": [
        {"case_id": "review-demo.example.test",
         "sequence": n,
         "packet_sha256": f"{n:064x}",
         "observed_at": f"2026-01-01T12:{n:02d}:00Z",
         "previous_packet_sha256": f"{n-1:064x}"}
        for n in range(1, count+1)
    ]}


def encode(data):
    return json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def invoke(raw, *options):
    return subprocess.run([sys.executable, "-m", MODULE, *options],
                          input=raw, capture_output=True, check=False, timeout=15,
                          env=dict(os.environ, PYTHONPATH="src"))


class TestLinkedFictionalCLI(unittest.TestCase):
    def hold(self, raw):
        outcome = parse_fictional_links(raw)
        self.assertEqual((outcome.status, outcome.checked_records), ("HOLD", 0))
        self.assertNotIn("review-demo", emit_review(outcome))
        for name in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(outcome, name), False)

    def test_actual_valid_process_is_review_only_exit_two(self):
        for count in (2, 3, 16):
            p = invoke(encode(source(count)))
            self.assertEqual(p.returncode, 2, p.stderr)
            result = json.loads(p.stdout)
            self.assertEqual((result["status"], result["checked_records"]), ("REVIEW_ONLY", count))
            for k in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
                self.assertIs(result[k], False)
            self.assertNotIn(b"review-demo", p.stdout + p.stderr)

    def test_bad_parent_from_valid_second_row_holds_at_process_boundary(self):
        fake = source()
        fake["records"][1]["previous_packet_sha256"] = "f"*64
        p = invoke(encode(fake))
        self.assertEqual(p.returncode, 3)
        self.assertEqual(json.loads(p.stdout)["status"], "HOLD")
        self.assertNotIn(b"review-demo", p.stdout + p.stderr)

    def test_real_two_fixture_processes(self):
        for name, expected, code in (
            ("fictional-links-1505-valid.json", "REVIEW_ONLY", 2),
            ("fictional-links-1505-broken.json", "HOLD", 3),
        ):
            proc = invoke((DOCS / name).read_bytes())
            self.assertEqual(proc.returncode, code, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["status"], expected)

    def test_alias_duplicate_unknown_and_reordered_fields_hold(self):
        valid = encode(source())
        for altered in (
            b" " + valid, valid+b"\n", valid+b"{}",
            valid.replace(b'"schema":', b'"schema":"fictional_handoff_links_v1","schema":', 1),
            valid.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1),
            valid.replace(b'"previous_packet_sha256"', b'"unexpected"', 1),
            valid.replace(b'"case_id":"review-demo.example.test","sequence":1',
                          b'"sequence":1,"case_id":"review-demo.example.test"', 1),
            valid.replace(b"review-demo", b"review-\\u0064emo", 1),
            valid.replace(b'"sequence":1', b'"sequence":true', 1),
        ):
            with self.subTest(altered=altered[:60]):
                self.hold(altered)

    def test_reject_bad_genesis_uppercase_parent_time_and_reused_hint(self):
        for update in (
            ("previous_packet_sha256", "f"*64),
            ("previous_packet_sha256", "0"*63+"g"),
            ("previous_packet_sha256", "A"*64),
            ("observed_at", "2026-02-30T12:02:00Z"),
            ("packet_sha256", "0"*64),
        ):
            payload = source()
            payload["records"][1][update[0]] = update[1]
            self.hold(encode(payload))

    def test_trail_nonbytes_unicode_wrong_container_and_oversize_hold(self):
        for raw in (None, "secret-string", bytearray(encode(source())),
                    b"", b"\xff", b"x"*8193, b"["+b"["*5000+b"]"*5000):
            self.hold(raw)

    def test_nonzero_on_disallowed_approve_and_bad_io(self):
        self.assertEqual(invoke(encode(source()), "--approve").returncode, 3)
        class BadReader:
            def read(self, _n):
                raise OSError("confidential review")
        output = io.StringIO()
        with patch("sys.argv", ["linked_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=BadReader())), \
             patch("sys.stdout", output):
            self.assertEqual(main(), 3)
        self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")
        self.assertNotIn("confidential", output.getvalue())
        class BrokenWriter:
            def write(self, _data):
                raise ValueError("confidential output")
        with patch("sys.argv", ["linked_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(encode(source())))), \
             patch("sys.stdout", BrokenWriter()):
            self.assertEqual(main(), 3)

    def test_real_fragmented_pipe_and_extra_data(self):
        raw = encode(source())
        for trailer, expected, code in ((b"", "REVIEW_ONLY", 2), (b"x", "HOLD", 3)):
            p = subprocess.Popen([sys.executable, "-m", MODULE],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 env=dict(os.environ, PYTHONPATH="src"))
            try:
                p.stdin.write(raw[:8])
                p.stdin.flush()
                p.stdin.write(raw[8:31])
                p.stdin.flush()
                stdout, stderr = p.communicate(raw[31:]+trailer, timeout=15)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()
            self.assertEqual(p.returncode, code, stderr)
            self.assertEqual(json.loads(stdout)["status"], expected)

    def test_jointly_fake_but_locally_coherent_is_never_consent(self):
        data = source(3)
        for row in data["records"]:
            n = row["sequence"]
            row["packet_sha256"] = f"{n+1000:064x}"
            row["previous_packet_sha256"] = "0"*64 if n == 1 else f"{n+999:064x}"
        r = parse_fictional_links(encode(data))
        self.assertEqual(r.status, "REVIEW_ONLY")
        for k in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(r, k), False)


if __name__ == "__main__":
    unittest.main()
