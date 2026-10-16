"""Offline CLI bounded stream-read error contract; no live targets or grants."""
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
sys.path.insert(0, str(ROOT / "src"))
CLI = ROOT / "scripts/review_scope_literal_controls_20261016.py"


class FailClosedWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = runpy.run_path(str(CLI), run_name="offline_scope_read_error_contract")

    def invoke(self, buffer):
        output = io.BytesIO()
        with patch.object(sys, "stdin", SimpleNamespace(buffer=buffer)):
            with patch.object(sys, "stdout", SimpleNamespace(buffer=output)):
                with patch("socket.socket", side_effect=AssertionError("network forbidden")):
                    with patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
                        with patch("builtins.open", side_effect=AssertionError("file forbidden")):
                            status = self.mod["main"]()
        return status, output.getvalue()

    def test_read_failure_is_generic_hold_not_traceback(self):
        for error in (OSError("private fictional stream path"), InterruptedError("interrupt")):
            class BrokenStream:
                def read(self, n):
                    self_size = self_outer.mod["_MAX_BYTES"] + 1
                    assert n == self_size
                    raise error

            self_outer = self
            exit_code, payload = self.invoke(BrokenStream())
            self.assertEqual(exit_code, 3)
            self.assertEqual(payload, self.mod["_HOLD"])
            self.assertNotIn(b"private fictional stream path", payload)

    def test_read_is_bounded_to_limit_plus_one(self):
        observed = []
        expected = b'{"authorities":["fictional.test"]}'

        class BoundedStream:
            def read(self, n):
                observed.append(n)
                if n != 8193:
                    raise AssertionError("unbounded input read")
                return expected

        code, output = self.invoke(BoundedStream())
        self.assertEqual(observed, [8193])
        self.assertEqual(code, 2)
        self.assertEqual(output, self.mod["_REVIEW"])

    def test_truncated_partial_read_fails_closed(self):
        class TruncatedStream:
            def read(self, n):
                self_seen.append(n)
                return b'{"authorities":["unfinished'

        self_seen = []
        code, output = self.invoke(TruncatedStream())
        self.assertEqual(self_seen, [8193])
        self.assertEqual(code, 3)
        self.assertEqual(output, self.mod["_HOLD"])

    def test_wire_messages_never_contain_permission(self):
        for status, wire in ((2, self.mod["_REVIEW"]), (3, self.mod["_HOLD"])):
            parsed = json.loads(wire)
            self.assertIn(parsed["status"], ("HOLD", "REVIEW_ONLY"))
            self.assertEqual(set(parsed), {
                "status", "authorized", "consent_verified", "dispatch_allowed", "release_allowed",
            })
            for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
                self.assertIs(parsed[field], False)
            self.assertIn(status, (2, 3))


if __name__ == "__main__":
    unittest.main()
