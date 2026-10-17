"""Conservative review-only aliases; none prove host or authorization identity."""
from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.scope_literal_control_review_20261016 import review_literals

CLI = ROOT / "scripts/review_scope_literal_controls_20261016.py"


class CollisionReviewTests(unittest.TestCase):
    def test_ascii_case_collisions_hold_atomically(self):
        for value in ("EXAMPLE.TEST", "Example.Test", "example.test"):
            with self.subTest(value=value):
                self.assertEqual(review_literals(("example.test", value)).status, "HOLD")

    def test_terminal_dot_collisions_hold(self):
        for aliases in (
            ("fictional.test", "fictional.test."),
            ("localhost", "LOCALHOST."),
            ("x.example.test.", "X.EXAMPLE.TEST.."),
        ):
            with self.subTest(aliases=aliases):
                self.assertEqual(review_literals(aliases).status, "HOLD")

    def test_userinfo_like_literals_cannot_gain_review_status(self):
        for value in (
            "http://fictional.test@outside.example.test",
            "operator@localhost", "user:pass@127.0.0.1",
        ):
            with self.subTest(value=value):
                decision = review_literals((value,))
                self.assertEqual(decision.status, "HOLD")
                self.assertFalse(decision.authorized)
                self.assertFalse(decision.consent_verified)

    def test_unrelated_literals_are_still_review_only(self):
        self.assertEqual(review_literals((
            "different-a.example.test",
            "different-b.example.test",
        )).status, "REVIEW_ONLY")

    def test_batch_reject_is_atomic_and_non_echoing_via_real_cli(self):
        for aliases in (
            ["fictional.test", "FICTIONAL.TEST"],
            ["fictional.test", "fictional.test."],
            ["http://allowed.example.test@elsewhere.test"],
        ):
            with self.subTest(aliases=aliases):
                encoded = json.dumps({"authorities": aliases}, separators=(",", ":")).encode("ascii")
                result = subprocess.run(
                    [sys.executable, str(CLI)], cwd=ROOT, input=encoded,
                    capture_output=True, check=False, timeout=8,
                )
                self.assertEqual(result.returncode, 3)
                self.assertEqual(json.loads(result.stdout)["status"], "HOLD")
                self.assertFalse(any(x is True for x in json.loads(result.stdout).values()))
                for literal in aliases:
                    self.assertNotIn(literal.encode("ascii"), result.stdout)
                self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
