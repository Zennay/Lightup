"""#1540 deterministic, real-file offline compare adapters fixtures (no live scans)."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "review_scope_compare_snapshots_offline_1540.py"
FIXTURES = ROOT / "examples"
spec = importlib.util.spec_from_file_location("scope1540_fixture_adapter", CLI)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class EndToEndFixtureTests(unittest.TestCase):
    def test_exact_fixtures_have_expected_fixed_exit_codes(self):
        for name, expected, code in (
            ("scope1540-compare-review-only.json", "REVIEW_ONLY", 3),
            ("scope1540-compare-overlap-hold.json", "HOLD", 2),
        ):
            with self.subTest(name=name):
                original = (FIXTURES / name).read_bytes()
                self.assertEqual(adapter.check(original), expected)
                proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(CLI)],
                                      input=original, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, timeout=10)
                self.assertEqual(proc.returncode, code, proc.stderr)
                self.assertEqual(proc.stderr, b"")
                result = json.loads(proc.stdout)
                self.assertEqual(result["status"], expected)
                self.assertEqual(len(result), 7)
                self.assertTrue(all(value is False for key, value in result.items()
                                    if key != "status"))
                self.assertNotIn(b"src/old.py", proc.stdout)

    def test_fixtures_are_canonical_strictly_synthetic(self):
        for path in FIXTURES.glob("scope1540-compare-*.json"):
            with self.subTest(path=path):
                raw = path.read_bytes()
                self.assertFalse(raw.endswith(b"\n"))
                doc = adapter.review._canonical_decode(raw)
                self.assertEqual(doc["version"], 1)
                self.assertEqual(len(doc["snapshots"]), 2)
                self.assertEqual(doc["base_sha"], "e" * 40)
                self.assertEqual({s["head_sha"] for s in doc["snapshots"]},
                                 {"a" * 40, "b" * 40})
                self.assertFalse(any("authorized" in s or "consent" in s
                                     for s in doc["snapshots"]))

    def test_corrupted_fixture_never_produces_review_only(self):
        data = (FIXTURES / "scope1540-compare-review-only.json").read_bytes()
        for candidate in (data[:-1], data + b"\n", data.replace(
                b'"compare_status":"ahead"', b'"compare_status":"diverged"'),
                data.replace(b'"behind_by":0', b'"behind_by":1'),
                data.replace(b'"expected_file_count":1', b'"expected_file_count":2')):
            with self.subTest(candidate=candidate[:24]):
                self.assertEqual(adapter.check(candidate), "HOLD")


if __name__ == "__main__":
    unittest.main()
