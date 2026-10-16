"""Real local subprocess pipe acceptance; no target, network or scan."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts/scope_ci_static_fence_cli_1509.py"
SOURCE = ROOT / ".github/workflows/lightup-ci.yml"


class StaticFenceCLITests(unittest.TestCase):
    def check_cli(self, payload, expected, code):
        proc = subprocess.run(
            [sys.executable, str(CLI)], input=payload, capture_output=True,
            cwd=ROOT, timeout=15, check=False
        )
        self.assertEqual(proc.returncode, code, proc.stderr)
        self.assertEqual(proc.stderr, b"")
        output = json.loads(proc.stdout)
        self.assertEqual(output.pop("state"), expected)
        self.assertEqual(output, {
            "authorized": False, "consent_verified": False,
            "dispatch_allowed": False, "release_allowed": False,
        })
        self.assertNotIn(b"self-hosted", proc.stdout)

    def test_actual_main_copy_is_review_only_nonzero(self):
        self.check_cli(SOURCE.read_bytes(), "REVIEW_ONLY", 2)

    def test_mutated_and_malformed_input_is_generic_hold(self):
        original = SOURCE.read_bytes()
        for payload in (
            b"", b"garbage", original.replace(b"vps-bb300bba", b"other-vps"),
            original + b"# injected data\n", original + b"\x00",
            b"\xff", original + b"X" * 20000,
        ):
            with self.subTest(size=len(payload)):
                self.check_cli(payload, "HOLD", 3)

    def test_fragmented_stdin_does_not_accidentally_approve(self):
        with subprocess.Popen(
            [sys.executable, str(CLI)], cwd=ROOT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) as proc:
            original = SOURCE.read_bytes()
            assert proc.stdin
            for part in (original[:10], original[10:100], original[100:]):
                proc.stdin.write(part)
                proc.stdin.flush()
            proc.stdin.close()
            assert proc.stdout and proc.stderr
            output = proc.stdout.read()
            err = proc.stderr.read()
            self.assertEqual(proc.wait(timeout=15), 2)
            self.assertEqual(err, b"")
            self.assertEqual(json.loads(output)["state"], "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
