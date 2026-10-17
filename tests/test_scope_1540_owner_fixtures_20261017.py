"""End-to-end standalone protected-source review regression (#1540)."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "review_scope_worker_ownership_offline_1540.py"
FIXTURES = ROOT / "examples"
spec = importlib.util.spec_from_file_location("scope1540_owner_fixture", CLI)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class OwnershipFixtureTests(unittest.TestCase):
    def test_exact_positive_and_negative_example_subprocesses(self):
        for filename, decision, code in (
            ("scope1540-owner-review-only.json", "REVIEW_ONLY", 3),
            ("scope1540-owner-hold.json", "HOLD", 2),
        ):
            with self.subTest(filename=filename):
                raw = (FIXTURES / filename).read_bytes()
                self.assertEqual(gate.check(raw), decision)
                process = subprocess.run([sys.executable, "-I", "-S", "-B", str(CLI)],
                                         input=raw, capture_output=True, timeout=10)
                self.assertEqual(process.returncode, code, process.stderr)
                self.assertEqual(process.stderr, b"")
                receipt = json.loads(process.stdout)
                self.assertEqual(receipt["status"], decision)
                self.assertEqual(set(receipt), {"status", *gate.review.FLAGS})
                self.assertTrue(all(receipt[key] is False for key in gate.review.FLAGS))
                self.assertNotIn(b"domain.py", process.stdout)

    def test_canonical_examples_use_only_fake_sha_and_repository(self):
        for p in FIXTURES.glob("scope1540-owner-*.json"):
            with self.subTest(path=p):
                raw = p.read_bytes()
                self.assertFalse(raw.endswith(b"\n"))
                record = gate.review._canonical_decode(raw)
                self.assertEqual(record["base_sha"], "d" * 40)
                self.assertEqual(record["repository_full_name"], "Example/Lightup")
                self.assertEqual({entry["pr"]["head_sha"] for entry in record["reviews"]},
                                 {"a" * 40, "b" * 40})
                self.assertEqual(set(record), {
                    "version", "base_sha", "repository_full_name", "reviews",
                    "ownership", "protected_paths"})
                self.assertTrue(all(e["pr"]["draft"] is True for e in record["reviews"]))

    def test_file_bytes_or_metadata_corruption_holds(self):
        good = (FIXTURES / "scope1540-owner-review-only.json").read_bytes()
        obj = json.loads(good)
        for transform in (
            lambda d: d["ownership"][0]["paths"].append("docs/extraneous.md"),
            lambda d: d["protected_paths"].clear(),
            lambda d: d["reviews"][1]["compare"]["files"][0].__setitem__(
                "filename", "tests/missing.py"),
            lambda d: d["reviews"][0]["pr"].__setitem__("head_sha", "c" * 40),
            lambda d: d["ownership"][1].__setitem__("head_sha", "f" * 40),
            lambda d: d["reviews"][1]["compare"].__setitem__(
                "repository_full_name", "Other/Lightup"),
        ):
            with self.subTest(transform=transform):
                entry = copy.deepcopy(obj)
                transform(entry)
                candidate = json.dumps(entry, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=True).encode("ascii")
                self.assertEqual(gate.check(candidate), "HOLD")
        for bad in (good[:-1], good + b"\n", b"\xef\xbb\xbf" + good):
            self.assertEqual(gate.check(bad), "HOLD")

    def test_no_external_io_when_validating_owned_file_paths(self):
        with (mock.patch("socket.socket", side_effect=AssertionError("network")),
              mock.patch("subprocess.run", side_effect=AssertionError("process")),
              mock.patch("builtins.open", side_effect=AssertionError("file"))):
            good = (FIXTURES / "scope1540-owner-review-only.json").read_bytes()
            self.assertEqual(gate.check(good), "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
