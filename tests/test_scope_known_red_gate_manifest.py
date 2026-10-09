"""Prevent green offline unit CI from being mistaken for resolved authorization."""
from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "scope-known-red-gates.json"


class KnownRedGateManifestTests(unittest.TestCase):
    def test_unresolved_gates_are_explicit_and_match_expected_failures(self):
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["status"], "DRAFT_HOLD")
        self.assertIs(data["activation_permitted"], False)
        self.assertEqual({item["issue"] for item in data["unresolved"]}, {1143, 1147})
        self.assertEqual(len(data["required_proof"]), len(set(data["required_proof"])))
        fixture_paths = (
            ROOT / "tests" / "test_scope_number_finiteness_contract.py",
            ROOT / "tests" / "test_scope_number_real_executor_contract.py",
        )
        marked = set()
        for path in fixture_paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if any(
                        isinstance(dec, ast.Attribute)
                        and isinstance(dec.value, ast.Name)
                        and dec.value.id == "unittest"
                        and dec.attr == "expectedFailure"
                        for dec in node.decorator_list
                    ):
                        marked.add(node.name)
        declared = [
            name
            for item in data["unresolved"]
            for name in item["expected_failure_tests"]
        ]
        self.assertEqual(len(declared), len(set(declared)))
        self.assertEqual(set(declared), marked)

    def test_manifest_is_fail_closed_and_requires_both_ci_environments(self):
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertFalse(data["activation_permitted"])
        self.assertEqual(data["status"], "DRAFT_HOLD")
        required = set(data["required_proof"])
        self.assertTrue({
            "same-head-hosted-python-3.11",
            "same-head-hosted-python-3.14",
            "same-head-vps-python-3.11",
            "same-head-vps-python-3.14",
            "source-owner-pre-io-grant-and-revocation",
            "source-owner-registry-network-destination",
            "independent-owner-review",
        }.issubset(required))
        self.assertGreater(len(data["unresolved"]), 0)

    def test_manifest_rejects_stale_or_fabricated_expected_failure_names(self):
        """All declared red gates must name test methods on owned fixtures."""
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        names = set()
        for path in (
            ROOT / "tests" / "test_scope_number_finiteness_contract.py",
            ROOT / "tests" / "test_scope_number_real_executor_contract.py",
        ):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            names.update(
                node.name for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("test_")
            )
        for entry in data["unresolved"]:
            self.assertIs(type(entry["issue"]), int)
            self.assertTrue(entry["key"])
            self.assertTrue(entry["expected_failure_tests"])
            self.assertTrue(set(entry["expected_failure_tests"]).issubset(names))


if __name__ == "__main__":
    unittest.main()
