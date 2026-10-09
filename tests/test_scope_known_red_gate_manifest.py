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


if __name__ == "__main__":
    unittest.main()
