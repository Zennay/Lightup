"""Real stdin subprocess controls for the standalone fictional #1505 CLI."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import io
from types import SimpleNamespace
from unittest.mock import patch
import sys
import unittest

from lightup.fictional_review_sequence_cli_1505 import (
    emit_review, parse_fictional_stdin, main, _read_bounded_to_eof,
)
from lightup.fictional_review_sequence_1505 import ReviewOutcome

CLI = "lightup.fictional_review_sequence_cli_1505"


def sample():
    return {"schema": "fictional_handoff_sequence_v1", "records": [
        {"case_id": "review-demo.example.test", "sequence": n,
         "packet_sha256": format(n, "064x"),
         "observed_at": "2026-01-01T12:0%d:00Z" % n}
        for n in (1, 2, 3)
    ]}


def encode(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def invoke(data, extra=()):
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    return subprocess.run([sys.executable, "-m", CLI, *extra],
                          input=data, capture_output=True, env=env,
                          timeout=15, check=False)


class TestFictionalCLI(unittest.TestCase):
    def assert_hold(self, blob):
        result = parse_fictional_stdin(blob)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.checked_records, 0)
        self.assertNotIn("demo.example.test", emit_review(result))
        self.assertFalse(any(getattr(result, k) for k in
            ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")))

    def test_positive_real_cli_has_only_non_authorizing_result(self):
        proc = invoke(encode(sample()))
        self.assertEqual(proc.returncode, 2, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual((result["status"], result["checked_records"]), ("REVIEW_ONLY", 3))
        self.assertEqual(len(result), 7)
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(result[key], False)
        self.assertNotIn(b"review-demo.example.test", proc.stdout)

    def test_bad_step_real_cli_is_hold_never_echo(self):
        data = sample()
        data["records"][1]["sequence"] = 4
        proc = invoke(encode(data))
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(json.loads(proc.stdout)["status"], "HOLD")
        self.assertNotIn(b"review-demo", proc.stdout + proc.stderr)

    def test_reject_noncanonical_whitespace_schema_field_order_escape(self):
        good = encode(sample())
        for changed in (b" "+good, good+b"\n", good.replace(b'":"', b'": "'),
                        good.replace(b'"schema"', b'"unknown"'),
                        good.replace(b"fictional_handoff_sequence_v1", b"other"),
                        good.replace(b"review-demo", b"review-\\u0064emo"),
                        good.replace(b'"schema":', b'"schema":"fictional_handoff_sequence_v1","schema":', 1),
                        good.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1),
                        good.replace(b'"case_id":"review-demo.example.test","sequence"',
                                     b'"sequence":1,"case_id":"review-demo.example.test","sequence"', 1)):
            self.assert_hold(changed)

    def test_reject_unicode_trailing_partial_nonbytes_and_massive(self):
        for blob in (b"", None, "text", bytearray(encode(sample())),
                     encode(sample())+b"{}", encode(sample())[:-3],
                     b"\xff", b'{"schema":"\xc3\xa9"}', b"["+b"["*3000+b"]"*3000,
                     b"x"*8193):
            self.assert_hold(blob)

    def test_real_cli_forbidden_flags_never_success(self):
        proc = invoke(encode(sample()), ["--approve"])
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(json.loads(proc.stdout)["status"], "HOLD")

    def test_reject_digest_reuse_even_when_envelope_is_canonical(self):
        data = sample()
        data["records"][2]["packet_sha256"] = data["records"][0]["packet_sha256"]
        self.assert_hold(encode(data))

    def test_emit_untrusted_outcome_after_low_level_tamper_is_hold(self):
        value = ReviewOutcome("REVIEW_ONLY", 2)
        object.__setattr__(value, "authorized", True)
        output = json.loads(emit_review(value))
        self.assertEqual((output["status"], output["checked_records"]), ("HOLD", 0))
        self.assertIs(output["authorized"], False)

    def test_canonical_examples_real_subprocess(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        for filename, expected, exitcode in (
            ("fictional-sequence-1505-valid.json", "REVIEW_ONLY", 2),
            ("fictional-sequence-1505-gap.json", "HOLD", 3),
        ):
            payload = (root / "docs" / "examples" / filename).read_bytes()
            proc = invoke(payload)
            self.assertEqual(proc.returncode, exitcode, (filename, proc.stderr))
            self.assertEqual(json.loads(proc.stdout)["status"], expected)



    def test_fragmented_bounded_reader_reassembles_canonical_payload(self):
        payload = encode(sample())

        class FragmentReader:
            def __init__(self, raw):
                self.raw = raw
                self.pos = 0
                self.calls = 0

            def read(self, maximum):
                self.calls += 1
                self.asserted_maximum = maximum
                data = self.raw[self.pos:self.pos + min(maximum, (self.calls % 7) + 1)]
                self.pos += len(data)
                return data

        reader = FragmentReader(payload)
        self.assertEqual(_read_bounded_to_eof(reader), payload)
        self.assertGreater(reader.calls, 20)
        self.assertLessEqual(reader.asserted_maximum, 8193)

        output = io.StringIO()
        with patch("sys.argv", ["review_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=FragmentReader(payload))), \
             patch("sys.stdout", output):
            self.assertEqual(main(), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "REVIEW_ONLY")

    def test_over_limit_is_generic_hold_before_second_poison_read(self):
        class OversizedReader:
            calls = 0
            def read(self, limit):
                self.calls += 1
                if self.calls > 1:
                    raise AssertionError("oversized stdin must not be read again")
                self.asserted_limit = limit
                return b"x" * limit

        reader = OversizedReader()
        output = io.StringIO()
        with patch("sys.argv", ["review_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=reader)), \
             patch("sys.stdout", output):
            self.assertEqual(main(), 3)
        self.assertEqual(reader.calls, 1)
        self.assertEqual(reader.asserted_limit, 8193)
        self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")
        self.assertNotIn("x", output.getvalue().split('"status":')[1])

    def test_nonbytes_and_bad_stream_are_hold_no_trace_or_echo(self):
        for chunk in (None, "secret-token", bytearray(b"secret-token"), 1234):
            class WeirdReader:
                def read(self, _n):
                    return chunk
            output = io.StringIO()
            with patch("sys.argv", ["review_cli"]), \
                 patch("sys.stdin", SimpleNamespace(buffer=WeirdReader())), \
                 patch("sys.stdout", output):
                self.assertEqual(main(), 3)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "HOLD")
            self.assertNotIn("secret", output.getvalue())

    def test_stdin_failure_and_broken_stdout_never_return_success(self):
        class FailedReader:
            def read(self, _n):
                raise OSError("confidential unreadable review data")

        output = io.StringIO()
        with patch("sys.argv", ["review_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=FailedReader())), \
             patch("sys.stdout", output):
            self.assertEqual(main(), 3)
        self.assertNotIn("confidential", output.getvalue())

        class BrokenWriter:
            def write(self, _):
                raise BrokenPipeError("closed stdout")
        with patch("sys.argv", ["review_cli"]), \
             patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(encode(sample())))), \
             patch("sys.stdout", BrokenWriter()):
            self.assertEqual(main(), 3)

    def test_real_subprocess_fragmented_pipe_and_trailing_data(self):
        env = dict(os.environ, PYTHONPATH="src")
        payload = encode(sample())
        for suffix, expected in ((b"", "REVIEW_ONLY"), (b"x", "HOLD")):
            process = subprocess.Popen(
                [sys.executable, "-m", CLI], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            )
            try:
                process.stdin.write(payload[:8])
                process.stdin.flush()
                process.stdin.write(payload[8:111])
                process.stdin.flush()
                stdout, stderr = process.communicate(payload[111:] + suffix, timeout=15)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            self.assertEqual(process.returncode, 2 if not suffix else 3, stderr)
            self.assertEqual(json.loads(stdout)["status"], expected)

if __name__ == "__main__":
    unittest.main()
