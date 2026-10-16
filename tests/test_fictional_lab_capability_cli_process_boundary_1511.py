"""#1511 opt-in single/batch CLI actual main() no-I/O execution boundary.

Pure offline acceptance: after imports, patch actual filesystem/network/process
constructors and call the *real* CLI main function with synthetic stdin.
Not a complete native syscall proof, runner proof, or authorization grant.
"""
import builtins
from contextlib import ExitStack
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fictional_lab_capability_cli_1511 import main as single_main
from fictional_lab_capability_batch_cli_1511 import main as batch_main


class _Stdin:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


_SINGLE = b'{"schema":"fictional_lab_capability_v1","requested":"web-baseline","allowlist":["web-baseline"]}'
_BATCH = b'{"schema":"fictional_lab_capability_batch_v1","requested":["web-baseline","tls-baseline"],"allowlist":["web-baseline","tls-baseline"]}'


def _run_hermetic(main, raw: bytes):
    output = io.StringIO()
    def _forbidden(*args, **kwargs):
        raise AssertionError("unexpected filesystem / network / process I/O from review")
    with ExitStack() as stack:
        stack.enter_context(patch.object(sys, "stdin", _Stdin(raw)))
        stack.enter_context(patch.object(sys, "stdout", output))
        for obj, name in (
            (builtins, "open"), (os, "open"), (os, "mkdir"), (os, "remove"),
            (os, "rename"), (os, "replace"), (os, "chdir"), (os, "system"),
            (subprocess, "Popen"), (socket, "socket"), (socket, "create_connection"),
            (Path, "open"), (Path, "write_text"), (Path, "write_bytes"),
            (Path, "mkdir"), (Path, "unlink"), (Path, "rename"),
        ):
            stack.enter_context(patch.object(obj, name, side_effect=_forbidden))
        code = main()
    return code, output.getvalue()


class FictionalLabCapabilityCLIProcessBoundary1511Tests(unittest.TestCase):
    def test_valid_single_main_nonzero_exit_and_no_io(self):
        self.assertEqual(_run_hermetic(single_main, _SINGLE), (2, "REVIEW_ONLY\n"))

    def test_valid_batch_main_nonzero_exit_and_no_io(self):
        self.assertEqual(_run_hermetic(batch_main, _BATCH), (2, "REVIEW_ONLY\n"))

    def test_invalid_single_main_generic_hold_no_io(self):
        self.assertEqual(_run_hermetic(single_main, _SINGLE + b" "), (3, "HOLD\n"))
        self.assertEqual(_run_hermetic(single_main, b"\xff" + _SINGLE), (3, "HOLD\n"))

    def test_invalid_batch_main_generic_hold_no_io(self):
        self.assertEqual(_run_hermetic(batch_main, _BATCH + b" "), (3, "HOLD\n"))
        self.assertEqual(_run_hermetic(batch_main, b"\x00"), (3, "HOLD\n"))

    def test_hostile_private_marker_no_echo_or_io(self):
        canary = b"PRIVATE_DO_NOT_LEAK_ANYWHERE"
        for main in (single_main, batch_main):
            for raw in (b'{"requested":"' + canary, canary + b"\x00"):
                with self.subTest(which=main.__module__, length=len(raw)):
                    code, text = _run_hermetic(main, raw)
                    self.assertEqual((code, text), (3, "HOLD\n"))
                    self.assertNotIn(canary.decode(), text)

    def test_no_code_path_ever_returns_success_for_short_synthetic_matrix(self):
        for main, valid in ((single_main, _SINGLE), (batch_main, _BATCH)):
            for raw in (b"", b"null", b"[]", b"{}", valid, valid[:1],
                        valid[:-1], valid + b"\n", valid + b"x" * 4100):
                with self.subTest(main=main.__module__, length=len(raw)):
                    code, out = _run_hermetic(main, raw)
                    self.assertIn(code, (2, 3))
                    self.assertIn(out, ("HOLD\n", "REVIEW_ONLY\n"))
                    self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
