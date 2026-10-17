"""#1540 canonical workflow HOLD fixture, red-green preservation."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_scope_worker_ownership_offline_1540.py"
SOURCE = ROOT / "examples" / "scope1540-invariant-critical-path-hold.json"
spec = importlib.util.spec_from_file_location("scope1540_hardhold_fixture", SCRIPT)
reviewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewer)


class FixedCriticalPolicyFixtureTests(unittest.TestCase):
    def test_fixture_is_canonical_and_deliberately_untrusted(self):
        raw = SOURCE.read_bytes()
        doc = reviewer.review._canonical_decode(raw)
        self.assertEqual(doc["repository_full_name"], "Example/Lightup")
        self.assertEqual(doc["base_sha"], "d" * 40)
        self.assertEqual(doc["protected_paths"], ["unrelated/fictional.txt"])
        self.assertEqual(doc["reviews"][1]["compare"]["files"][0]["filename"],
                         ".github/workflows/fictional-release.yml")
        self.assertEqual(doc["ownership"][1]["paths"],
                         [".github/workflows/fictional-release.yml"])

    def test_even_exact_owner_claim_cannot_bypass_fixed_control_plane(self):
        data = SOURCE.read_bytes()
        self.assertEqual(reviewer.check(data), "HOLD")
        process = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                                 input=data, capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(process.stderr, b"")
        payload = json.loads(process.stdout)
        self.assertEqual(payload["status"], "HOLD")
        self.assertEqual(set(payload), {"status", *reviewer.review.FLAGS})
        self.assertTrue(all(payload[k] is False for k in reviewer.review.FLAGS))
        self.assertNotIn(b"fictional-release", process.stdout)

    def test_bad_bytes_cannot_fall_back_to_review(self):
        data = SOURCE.read_bytes()
        for changed in (data[:-1], data + b"\n", b" "+data):
            with self.subTest(length=len(changed)):
                self.assertEqual(reviewer.check(changed), "HOLD")


if __name__ == "__main__":
    unittest.main()
