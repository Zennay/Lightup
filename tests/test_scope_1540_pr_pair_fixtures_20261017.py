"""Standalone fictional PR+compare pair protocol regression fixtures (#1540)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_scope_pr_compare_pair_offline_1540.py"
EXAMPLES = ROOT / "examples"
spec = importlib.util.spec_from_file_location("scope1540_pair_fixture", SCRIPT)
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)


class PairFixtureTests(unittest.TestCase):
    def test_canonical_example_receipts_and_exit_codes(self):
        for filename, expected, code in (
            ("scope1540-pr-pair-review-only.json", "REVIEW_ONLY", 3),
            ("scope1540-pr-pair-hold.json", "HOLD", 2),
        ):
            with self.subTest(filename=filename):
                data = (EXAMPLES / filename).read_bytes()
                self.assertEqual(pair.check(data), expected)
                result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                                        input=data, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stderr, b"")
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["status"], expected)
                self.assertEqual(set(receipt), {"status", *pair.review.FLAGS})
                self.assertTrue(all(receipt[key] is False for key in pair.review.FLAGS))
                self.assertNotIn(b"before.py", result.stdout)

    def test_fixtures_never_claim_real_source_or_authority(self):
        for path in EXAMPLES.glob("scope1540-pr-pair-*.json"):
            with self.subTest(path=path):
                original = path.read_bytes()
                doc = pair.review._canonical_decode(original)
                self.assertEqual(doc["repository_full_name"], "Example/Lightup")
                self.assertEqual(doc["base_sha"], "d" * 40)
                self.assertEqual(doc["version"], 1)
                self.assertEqual({v["pr"]["head_sha"] for v in doc["reviews"]},
                                 {"a" * 40, "b" * 40})
                self.assertEqual({v["pr"]["draft"] for v in doc["reviews"]}, {True})
                self.assertNotIn("release_allowed", doc)
                self.assertNotIn("consent_verified", doc)

    def test_mutating_any_sha_or_repository_identity_forces_hold(self):
        orig = json.loads((EXAMPLES / "scope1540-pr-pair-review-only.json").read_text())
        for selector in (
            lambda d: d["reviews"][0]["pr"].__setitem__("head_sha", "c" * 40),
            lambda d: d["reviews"][1]["compare"].__setitem__("head_sha", "c" * 40),
            lambda d: d["reviews"][0]["pr"].__setitem__("head_repo_full_name", "Another/Repo"),
            lambda d: d["reviews"][0]["compare"].__setitem__("repository_full_name", "Another/Repo"),
            lambda d: d.__setitem__("repository_full_name", "Another/Repo"),
        ):
            with self.subTest(selector=selector):
                data = json.loads(json.dumps(orig))
                selector(data)
                raw = json.dumps(data, sort_keys=True, ensure_ascii=True,
                                 separators=(",", ":")).encode("ascii")
                self.assertEqual(pair.check(raw), "HOLD")


if __name__ == "__main__":
    unittest.main()
