"""Issue #1511: genuine fragmented-stdin and bounded canonical JSON tests.

Only process under test is the own, standalone non-authorizing CLI.  No real
targets, external network, grants, adapters or production activation.
"""
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from fictional_lab_capability_cli_1511 import decide_stdin_bytes_1511

CLI = ROOT / "scripts" / "fictional_lab_capability_cli_1511.py"
VALID = (b'{"schema":"fictional_lab_capability_v1","requested":"web-baseline",'
         b'"allowlist":["web-baseline","tls-baseline"]}')


def _process():
    return subprocess.Popen(
        [sys.executable, str(CLI)], cwd=ROOT,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


class FictionalLabCapabilityStreaming1511Tests(unittest.TestCase):
    def test_genuine_fragmented_pipe_at_eight_boundaries(self):
        for boundary in (1, 2, 8, 20, len(VALID) // 2, len(VALID) - 2, len(VALID) - 1):
            with self.subTest(boundary=boundary):
                proc = _process()
                try:
                    proc.stdin.write(VALID[:boundary])
                    proc.stdin.flush()
                    out, err = proc.communicate(input=VALID[boundary:], timeout=10)
                    self.assertEqual((proc.returncode, out, err), (2, b"REVIEW_ONLY\n", b""))
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=10)

    def test_partial_canonical_input_without_final_eof_is_not_authority(self):
        for length in (0, 1, 3, len(VALID) - 1):
            with self.subTest(length=length):
                proc = _process()
                try:
                    out, err = proc.communicate(input=VALID[:length], timeout=10)
                    self.assertEqual((proc.returncode, out, err), (3, b"HOLD\n", b""))
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=10)

    def test_every_prefix_is_hold_without_completing_full_object(self):
        for offset in range(len(VALID)):
            self.assertEqual(decide_stdin_bytes_1511(VALID[:offset]), "HOLD")
        self.assertEqual(decide_stdin_bytes_1511(VALID), "REVIEW_ONLY")

    def test_exact_4096_and_overlong_input_fail_closed(self):
        sample4096 = VALID + b" " * (4096 - len(VALID))
        self.assertEqual(len(sample4096), 4096)
        self.assertEqual(decide_stdin_bytes_1511(sample4096), "HOLD")
        self.assertEqual(decide_stdin_bytes_1511(sample4096 + b"x"), "HOLD")
        proc = _process()
        try:
            out, err = proc.communicate(input=sample4096 + b"x", timeout=10)
            self.assertEqual((proc.returncode, out, err), (3, b"HOLD\n", b""))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=10)

    def test_duplicate_unicode_alias_keys_and_floats_hold(self):
        suspicious = (
            VALID.replace(b'"schema":', b'"\\u0073chema":"fictional_lab_capability_v1","schema":'),
            VALID.replace(b'"schema":', b'"schema":"fictional_lab_capability_v1","\\u0073chema":'),
            VALID.replace(b'"requested":"web-baseline"', b'"requested":NaN'),
            VALID.replace(b'"requested":"web-baseline"', b'"requested":Infinity'),
            VALID.replace(b'"requested":"web-baseline"', b'"requested":-Infinity'),
            VALID.replace(b'"requested":"web-baseline"', b'"requested":1e99999'),
            VALID.replace(b'"requested":"web-baseline"', b'"requested":[]'),
        )
        for input_bytes in suspicious:
            with self.subTest(sample=input_bytes[:64]):
                self.assertEqual(decide_stdin_bytes_1511(input_bytes), "HOLD")

    def test_deeply_nested_input_does_not_crash_to_success(self):
        for depth in (100, 700, 1500):
            raw = b"[" * depth + b"0" + b"]" * depth
            self.assertLessEqual(len(raw), 4096)
            self.assertEqual(decide_stdin_bytes_1511(raw), "HOLD")

    def test_incomplete_json_with_private_marker_never_echoed(self):
        marker = b"PRIVATE_SCOPE_MARKER_DO_NOT_ECHO"
        proc = _process()
        try:
            out, err = proc.communicate(input=b'{"requested":"' + marker, timeout=10)
            self.assertEqual((proc.returncode, out, err), (3, b"HOLD\n", b""))
            self.assertNotIn(marker, out + err)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
