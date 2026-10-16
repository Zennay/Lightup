"""Real subprocess, no-echo, bounded offline #1517 fictional JSON CLI acceptance."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scope_target_binding_review_cli_1517.py"
FIRST = ["case.example.test", "owner-alpha", "grant-alpha", 7]
FINE = {"pairs": [[FIRST, FIRST]]}
NO_RIGHTS = {
    "authorized": False, "consent_verified": False,
    "dispatch_allowed": False, "release_allowed": False,
}


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


class TargetBindingCLI1517Tests(unittest.TestCase):
    @staticmethod
    def invoke(payload: bytes):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT)],
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=ROOT, env=env, timeout=10, check=False,
        )

    def assert_receipt(self, response, status):
        self.assertEqual(response.returncode, 2 if status == "REVIEW_ONLY" else 3)
        self.assertEqual(response.stderr, b"")
        self.assertEqual(json.loads(response.stdout), {"status": status, **NO_RIGHTS})
        self.assertEqual(response.stdout.count(b"\n"), 1)
        self.assertNotIn(b"case.example.test", response.stdout)
        self.assertNotIn(b"owner-alpha", response.stdout)
        self.assertNotIn(b"grant-alpha", response.stdout)

    def test_valid_canonical_fictional_packet_returns_nonzero_review(self):
        self.assert_receipt(self.invoke(canonical(FINE)), "REVIEW_ONLY")

    def test_atomically_holds_one_changed_identity(self):
        bad = {"pairs": [[FIRST, [FIRST[0], "owner-beta", FIRST[2], 7]]]}
        self.assert_receipt(self.invoke(canonical(bad)), "HOLD")

    def test_all_canonical_structural_rejections(self):
        for value in (
            None, [], {}, {"pairs": []}, {"pairs": [FIRST]},
            {"pairs": [[FIRST]]}, {"pairs": [[[FIRST[0]], FIRST]]},
            {"pairs": [[FIRST, FIRST], [FIRST, FIRST]]},
            {"pairs": [[FIRST, FIRST]], "approved": True},
            {"approved": True, "pairs": [[FIRST, FIRST]]},
            {"pairs": [[FIRST, [FIRST[0], FIRST[1], FIRST[2], True]]]},
        ):
            with self.subTest(value=repr(value)[:80]):
                self.assert_receipt(self.invoke(canonical(value)), "HOLD")

    def test_byte_exact_and_hostile_rfc_json(self):
        base = canonical(FINE)
        variants = (
            b"", b" ", base + b"\n", b" " + base,
            base + b"extra", b"\xef\xbb\xbf" + base,
            base.replace(b"case", b"Case", 1),
            base.replace(b"case", b"\\u0063ase", 1),
            base.replace(b"7", b"NaN", 1),
            base.replace(b"7", b"Infinity", 1),
            base.replace(b"7", b"-Infinity", 1),
            base.replace(b"7", b"1.0", 1),
            base.replace(b"7", b"true", 1),
            base.replace(b"7", b"null", 1),
            b"\x00" + base,
            b"[" * 1100 + b"0" + b"]" * 1100,
            b"x" * 16385,
            b'{"pairs":[],"pairs":[]}',
        )
        for i, data in enumerate(variants):
            with self.subTest(case=i):
                self.assert_receipt(self.invoke(data), "HOLD")

    def test_valid_max_cohort_and_invalid_65th(self):
        cohort = [
            [
                [f"case{i}.example.test", f"owner-{i}", f"grant-{i}", i + 1],
                [f"case{i}.example.test", f"owner-{i}", f"grant-{i}", i + 1],
            ]
            for i in range(65)
        ]
        self.assert_receipt(self.invoke(canonical({"pairs": cohort[:64]})), "REVIEW_ONLY")
        self.assert_receipt(self.invoke(canonical({"pairs": cohort})), "HOLD")

    def test_all_single_nul_corruptions_fail_without_echo(self):
        valid = canonical(FINE)
        for i in range(len(valid)):
            with self.subTest(index=i):
                self.assert_receipt(self.invoke(valid[:i] + b"\x00" + valid[i+1:]), "HOLD")

    def test_split_stdin_real_eof(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        proc = subprocess.Popen(
            [sys.executable, "-B", str(SCRIPT)], cwd=ROOT, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            raw = canonical(FINE)
            for position in range(0, len(raw), 7):
                proc.stdin.write(raw[position:position + 7])
                proc.stdin.flush()
            proc.stdin.close()
            proc.stdin = None
            output, error = proc.communicate(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(error, b"")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(output), {"status": "REVIEW_ONLY", **NO_RIGHTS})


if __name__ == "__main__":
    unittest.main()
