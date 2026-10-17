"""Query/fragment loss risks in fictional pasted authority review.

These are *review-only* syntactic fences, never real admission decisions.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.scope_literal_control_review_20261016 import review_literals

CLI = ROOT / "scripts/review_scope_literal_controls_20261016.py"


class QueryFragmentReviewTests(unittest.TestCase):
    def test_query_and_fragment_ambiguity_hold(self):
        for candidate in (
            "fictional.example.test?mode=other",
            "fictional.example.test#operator-note",
            "http://localhost/?redirect=public.example.test",
            "https://localhost/#allow",
            "localhost#@other.example.test",
            "127.0.0.1?capability=scan",
            "lab.example.test?#",
        ):
            with self.subTest(value=candidate):
                review = review_literals((candidate,))
                self.assertEqual(review.status, "HOLD")
                self.assertFalse(review.authorized)
                self.assertFalse(review.consent_verified)
                self.assertFalse(review.dispatch_allowed)
                self.assertFalse(review.release_allowed)

    def test_one_unsafe_candidate_poison_entire_batch_without_input_echo(self):
        for injected in ("private.example.test?grant=true", "private.example.test#approved"):
            values = ["fictional.example.test", "lab.example.test", injected]
            self.assertEqual(review_literals(tuple(values)).status, "HOLD")
            wire = json.dumps({"authorities": values}, separators=(",", ":")).encode("ascii")
            done = subprocess.run(
                [sys.executable, str(CLI)], input=wire, capture_output=True,
                check=False, cwd=ROOT, timeout=10,
            )
            self.assertEqual(done.returncode, 3)
            data = json.loads(done.stdout)
            self.assertEqual(data["status"], "HOLD")
            self.assertFalse(any(value is True for value in data.values()))
            self.assertNotIn(b"private.example.test", done.stdout)
            self.assertNotIn(b"fictional.example.test", done.stdout)
            self.assertEqual(done.stderr, b"")

    def test_distinct_plain_literals_still_review_only(self):
        self.assertEqual(review_literals((
            "fictional.example.test", "lab.example.test",
        )).status, "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
