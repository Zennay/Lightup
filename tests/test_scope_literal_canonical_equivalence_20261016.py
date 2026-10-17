"""RFC JSON spelling ambiguity and alias resistance for fictional review wire.

All test names/targets are synthetic; no real authorization or network.
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
VALID = b'{"authorities":["fictional.example.test","lab.example.test"]}'


class CanonicalWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = runpy.run_path(str(CLI), run_name="offline_canonical_intake_test")

    def invoke(self, packet: bytes):
        sink = io.BytesIO()
        with patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(packet))), \
             patch.object(sys, "stdout", SimpleNamespace(buffer=sink)), \
             patch("socket.socket", side_effect=AssertionError("no network")), \
             patch("subprocess.Popen", side_effect=AssertionError("no process")), \
             patch("builtins.open", side_effect=AssertionError("no file open")):
            code = self.mod["main"]()
        return code, sink.getvalue()

    def assert_hold(self, payload: bytes):
        code, output = self.invoke(payload)
        self.assertEqual(code, 3, payload[:60])
        self.assertEqual(output, self.mod["_HOLD"])
        self.assertNotIn(b"fictional.example.test", output)
        self.assertFalse(any(v is True for v in json.loads(output).values()))

    def test_exact_canonical_control_is_non_authorizing_review_only(self):
        code, output = self.invoke(VALID)
        self.assertEqual(code, 2)
        self.assertEqual(output, self.mod["_REVIEW"])
        self.assertFalse(any(v is True for v in json.loads(output).values()))

    def test_ascii_whitespace_insertions_at_every_boundary(self):
        for pos in range(len(VALID) + 1):
            for value in (b" ", b"\t", b"\r", b"\n"):
                packet = VALID[:pos] + value + VALID[pos:]
                with self.subTest(pos=pos, value=value):
                    self.assert_hold(packet)

    def test_equivalent_escaped_spellings_are_not_accepted(self):
        canonical = b'{"authorities":["fictional.example.test"]}'
        self.assertEqual(self.invoke(canonical)[0], 2)
        spellings = (
            b'{"authorities":["fictional\\u002eexample.test"]}',
            b'{"authorities":["\\u0066ictional.example.test"]}',
            b'{"authorities":["fictional.example\\u002etest"]}',
            b'{"\\u0061uthorities":["fictional.example.test"]}',
            b'{"authorities":["fictional.example.test"],"authorities":[]}',
            b'{"authorities":["fictional.example.test"],"other":null}',
            b'{"authorities":["fictional.example.test",]}',
            b'{ "authorities":["fictional.example.test"]}',
            b'{"authorities": ["fictional.example.test"]}',
            b'{"authorities":["fictional.example.test"] }',
            b'{"authorities":["fictional.example.test"]}\n',
            b'{"authorities":["fictional.example.test"]}\x00',
            b'\xef\xbb\xbf{"authorities":["fictional.example.test"]}',
        )
        for item in spellings:
            with self.subTest(raw=item):
                self.assert_hold(item)

    def test_candidate_order_and_distinct_entries_are_not_normalized(self):
        forward = VALID
        reverse = b'{"authorities":["lab.example.test","fictional.example.test"]}'
        self.assertEqual(self.invoke(forward), (2, self.mod["_REVIEW"]))
        self.assertEqual(self.invoke(reverse), (2, self.mod["_REVIEW"]))
        # But case/dot aliases are not independent review entries.
        for values in (
            ("lab.example.test", "LAB.EXAMPLE.TEST"),
            ("lab.example.test", "lab.example.test."),
        ):
            packet = json.dumps({"authorities": list(values)}, separators=(",", ":")).encode("ascii")
            self.assert_hold(packet)


if __name__ == "__main__":
    unittest.main()
