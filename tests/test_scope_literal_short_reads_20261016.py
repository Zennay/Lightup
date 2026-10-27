"""Stream-framing regressions for the isolated non-authorizing scope CLI.

A short read is NOT an end-of-message signal. No network, grants or targets.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import runpy
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "review_scope_literal_controls_20261016.py"


class PartialReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = runpy.run_path(str(CLI), run_name="offline_partial_stream_test")

    def invoke(self, stream):
        output = io.BytesIO()
        with patch.object(sys, "stdin", SimpleNamespace(buffer=stream)), \
             patch.object(sys, "stdout", SimpleNamespace(buffer=output)), \
             patch("socket.socket", side_effect=AssertionError("no sockets")), \
             patch("subprocess.Popen", side_effect=AssertionError("no children")), \
             patch("builtins.open", side_effect=AssertionError("no file opens")):
            code = self.module["main"]()
        self.assertIn(code, (2, 3))
        self.assertIn(output.getvalue(), (self.module["_REVIEW"], self.module["_HOLD"]))
        return code, output.getvalue()

    def test_valid_one_byte_reads_until_eof(self):
        data = b'{"authorities":["fictional.example.test"]}'
        class Stream:
            def __init__(self):
                self.remaining = data
                self.calls = 0
            def read(self, amount):
                self.calls += 1
                self.assert_limit = amount
                assert 1 <= amount <= 8193
                chunk, self.remaining = self.remaining[:1], self.remaining[1:]
                return chunk

        stream = Stream()
        code, output = self.invoke(stream)
        self.assertEqual(code, 2)
        self.assertEqual(output, self.module["_REVIEW"])
        self.assertEqual(stream.calls, len(data) + 1)

    def test_valid_prefix_followed_by_trailing_data_cannot_pass(self):
        prefix = b'{"authorities":["fictional.example.test"]}'
        for suffix in (b" ", b'{"authorities":["another.test"]}', b"\x00"):
            with self.subTest(suffix=suffix):
                class Stream:
                    def __init__(self):
                        self.blocks = [prefix, suffix]
                    def read(self, amount):
                        if not self.blocks:
                            return b""
                        block = self.blocks.pop(0)
                        assert len(block) <= amount
                        return block
                code, output = self.invoke(Stream())
                self.assertEqual(code, 3)
                self.assertEqual(output, self.module["_HOLD"])

    def test_fragmented_valid_packet_remains_review_only(self):
        payload = b'{"authorities":["fictional.test","lab.example.test"]}'
        for size in (1, 2, 3, 7, 13):
            with self.subTest(chunk_size=size):
                class Stream:
                    def __init__(self):
                        self.buffer = io.BytesIO(payload)
                    def read(self, amount):
                        return self.buffer.read(min(size, amount))
                code, output = self.invoke(Stream())
                self.assertEqual((code, output), (2, self.module["_REVIEW"]))

    def test_oversized_stream_fails_after_bounded_read(self):
        class Stream:
            def __init__(self):
                self.total = 0
            def read(self, amount):
                assert 1 <= amount <= 8193
                self.total += amount
                return b"x" * amount
        stream = Stream()
        code, output = self.invoke(stream)
        self.assertEqual(code, 3)
        self.assertEqual(output, self.module["_HOLD"])
        self.assertEqual(stream.total, 8193)

    def test_exception_after_valid_prefix_is_generic_hold(self):
        prefix = b'{"authorities":["fictional.test"]}'
        class Stream:
            def __init__(self):
                self.calls = 0
            def read(self, amount):
                self.calls += 1
                if self.calls == 1:
                    return prefix
                raise OSError("fictional private source label")
        code, output = self.invoke(Stream())
        self.assertEqual(code, 3)
        self.assertEqual(output, self.module["_HOLD"])
        self.assertNotIn(b"fictional", output)

    def test_oversized_fragment_from_nonconforming_stream_is_hold(self):
        class BrokenStream:
            def read(self, amount):
                return b"x" * (amount + 1)
        self.assertEqual(self.invoke(BrokenStream()), (3, self.module["_HOLD"]))

    def test_bytes_subclass_is_not_trusted(self):
        class SpoofedBytes(bytes):
            pass
        class BrokenStream:
            def read(self, amount):
                return SpoofedBytes(b'{"authorities":["fictional.test"]}')
        self.assertEqual(self.invoke(BrokenStream()), (3, self.module["_HOLD"]))

    def test_exact_boundary_one_byte_fragments(self):
        entries = [f"fictional-{i:02d}-" + "x" * 100 for i in range(50)]
        import json
        def encode():
            return json.dumps({"authorities": entries}, separators=(",", ":")).encode("ascii")
        budget = 8192 - len(encode())
        for i, item in enumerate(entries):
            addition = min(budget, 512 - len(item))
            entries[i] += "z" * addition
            budget -= addition
            if budget == 0:
                break
        self.assertEqual(len(encode()), 8192)
        class Stream:
            def __init__(self, data):
                self.data = io.BytesIO(data)
                self.total = 0
            def read(self, amount):
                assert 1 <= amount <= 1024
                chunk = self.data.read(min(amount, 1))
                self.total += len(chunk)
                return chunk
        at_limit = Stream(encode())
        self.assertEqual(self.invoke(at_limit), (2, self.module["_REVIEW"]))
        self.assertEqual(at_limit.total, 8192)
        over_limit = Stream(encode() + b"x")
        self.assertEqual(self.invoke(over_limit), (3, self.module["_HOLD"]))
        self.assertEqual(over_limit.total, 8193)

    def test_nonbytes_read_result_fails_closed(self):
        for part in ("not bytes", None, bytearray(b"hi"), memoryview(b"hi")):
            with self.subTest(kind=type(part).__name__):
                class Stream:
                    def read(self, amount):
                        return part
                self.assertEqual(self.invoke(Stream()), (3, self.module["_HOLD"]))


if __name__ == "__main__":
    unittest.main()
