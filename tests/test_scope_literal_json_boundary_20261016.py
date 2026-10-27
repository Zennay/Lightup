"""Bounded canonical JSON/malformed byte stream evidence for offline scope reviewer."""
from __future__ import annotations

import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.scope_literal_control_review_20261016 import LiteralReview

CLI = ROOT / "scripts/review_scope_literal_controls_20261016.py"


def _invoke_in_process(main, data: bytes) -> tuple[int, bytes]:
    output = io.BytesIO()
    with patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(data))):
        with patch.object(sys, "stdout", SimpleNamespace(buffer=output)):
            code = main()
    return code, output.getvalue()


class BoundedLiteralWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cli = runpy.run_path(str(CLI), run_name="offline_literal_boundary_tests")
        cls.review, cls.hold = cls.cli["_REVIEW"], cls.cli["_HOLD"]

    def test_canonical_exact_8192_byte_payload_and_8193_hold(self):
        names = [f"fake-{index:02d}-" + ("x" * 100) for index in range(50)]

        def serialize():
            return json.dumps({"authorities": names}, separators=(",", ":"), ensure_ascii=True).encode("ascii")

        budget = 8192 - len(serialize())
        self.assertGreater(budget, 0)
        for index in range(len(names)):
            extend = min(budget, 512 - len(names[index]))
            names[index] += "y" * extend
            budget -= extend
            if budget == 0:
                break
        self.assertEqual(budget, 0)
        full = serialize()
        self.assertEqual(len(full), 8192)
        result = subprocess.run([sys.executable, str(CLI)], input=full, capture_output=True, cwd=ROOT, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, self.review)
        self.assertEqual(result.stderr, b"")
        over = subprocess.run([sys.executable, str(CLI)], input=full + b" ", capture_output=True, cwd=ROOT, timeout=10)
        self.assertEqual(over.returncode, 3, over.stderr)
        self.assertEqual(over.stdout, self.hold)
        self.assertEqual(over.stderr, b"")

    def test_all_mutations_of_canonical_wire_never_echo_or_authorize(self):
        seed = b'{"authorities":["fictional.test"]}'
        main = self.cli["main"]
        with patch("socket.socket", side_effect=AssertionError("network denied")):
            with patch("subprocess.Popen", side_effect=AssertionError("process denied")):
                with patch("builtins.open", side_effect=AssertionError("file denied")):
                    for position in range(len(seed)):
                        for number in range(128):
                            changed = seed[:position] + bytes([number]) + seed[position + 1:]
                            code, output = _invoke_in_process(main, changed)
                            self.assertIn(code, (2, 3))
                            self.assertIn(output, (self.review, self.hold))
                            self.assertNotIn(b"fictional.test", output)

    def test_invalid_unicode_bytes_and_surrogate_never_print_input(self):
        main = self.cli["main"]
        payloads = [
            b'{"authorities":["ok\xff"]}', b'{"authorities":["ok\xc0\xaf"]}',
            b'{"authorities":["\x00"]}', b'{"authorities":["\\ud800"]}',
            b'{"authorities":["\\udc00"]}', b'{"authorities":["\\u202e"]}',
            b'{"authorities":[{}]}', b'{"authorities":[{"authorities":["ok"]}]}',
            b'{"authorities":' + (b"[" * 3000) + b"0" + (b"]" * 3000) + b"}",
        ]
        for data in payloads:
            with self.subTest(data=data[:40]):
                code, output = _invoke_in_process(main, data)
                self.assertEqual(code, 3)
                self.assertEqual(output, self.hold)

    def test_literal_review_rejects_forged_status_types(self):
        class StatusStr(str):
            def __eq__(self, _other):
                raise AssertionError("do not invoke subclass")
        for supplied in (b"REVIEW_ONLY", StatusStr("REVIEW_ONLY"), None, True, "", "AUTHORIZED", "GO"):
            with self.subTest(type=type(supplied).__name__):
                with self.assertRaises(ValueError):
                    LiteralReview(supplied)
        for supplied in ("HOLD", "REVIEW_ONLY"):
            status = LiteralReview(supplied)
            self.assertEqual(status.status, supplied)
            self.assertFalse(status.authorized)
            self.assertFalse(status.consent_verified)
            self.assertFalse(status.dispatch_allowed)
            self.assertFalse(status.release_allowed)


if __name__ == "__main__":
    unittest.main()
