"""Static fail-closed isolation tripwires for #1505 (no dynamic source execution)."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "lightup"
PREFIX = "fictional_review_sequence"
OWN = (
    "fictional_review_sequence_1505.py",
    "fictional_review_sequence_cli_1505.py",
    "fictional_review_sequence_compare_1505.py",
    "fictional_review_sequence_pair_cli_1505.py",
    "fictional_review_sequence_segments_1505.py",
    "fictional_review_sequence_segments_cli_1505.py",
    "fictional_review_sequence_anchor_1505.py",
    "fictional_review_sequence_anchor_cli_1505.py",
    "fictional_review_sequence_linked_1505.py",
    "fictional_review_sequence_linked_cli_1505.py",
)
MODULES = tuple("lightup." + filename[:-3] for filename in OWN)


def literal_dynamic_import(node: ast.Call) -> str | None:
    fn = node.func
    if isinstance(fn, ast.Name) and fn.id == "__import__":
        pass
    elif (isinstance(fn, ast.Attribute) and fn.attr == "import_module"
          and isinstance(fn.value, ast.Name) and fn.value.id == "importlib"):
        pass
    else:
        return None
    if node.args and isinstance(node.args[0], ast.Constant) and type(node.args[0].value) is str:
        return node.args[0].value
    return None


class TestFictionalReviewModuleIsolation(unittest.TestCase):
    def test_existing_production_tree_cannot_statically_import_own_review_code(self):
        checked = 0
        for path in sorted(SOURCE.rglob("*.py")):
            if path.name in OWN:
                continue
            tree = ast.parse(path.read_bytes(), filename=str(path))
            checked += 1
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(alias.name.startswith("lightup." + PREFIX),
                                         (path.name, "forbidden direct runtime import"))
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        self.assertFalse(node.module.startswith("lightup." + PREFIX)
                                         or node.module.startswith(PREFIX),
                                         (path.name, "forbidden from-import"))
                    if node.module in (None, "lightup") and node.level in (0, 1):
                        for alias in node.names:
                            self.assertFalse(alias.name.startswith(PREFIX),
                                             (path.name, "forbidden relative import"))
                elif isinstance(node, ast.Call):
                    candidate = literal_dynamic_import(node)
                    self.assertFalse(candidate and candidate.startswith("lightup." + PREFIX),
                                     (path.name, "literal dynamic import"))
        self.assertGreater(checked, 10)

    def test_owned_modules_only_use_stdlib_or_own_companions(self):
        allowed = {"__future__", "dataclasses", "datetime", "re", "json", "sys"}
        for filename in OWN:
            tree = ast.parse((SOURCE / filename).read_bytes(), filename=filename)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module] if node.module else []
                else:
                    continue
                for module in names:
                    self.assertTrue(module in allowed or module in MODULES,
                                    (filename, "foreign import", module))
            forbidden_calls = ("eval", "exec", "compile", "open", "__import__")
            self.assertFalse(any(
                isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in forbidden_calls for node in ast.walk(tree)
            ), (filename, "unsafe dynamic code/filesystem call"))

    def test_own_ci_stays_hosted_readonly_path_filtered_and_no_deploy(self):
        content = (ROOT / ".github/workflows/scope-fictional-review-sequence-1505.yml").read_text()
        for required in ("pull_request:", "paths:", "permissions:\n  contents: read",
                         "runs-on: ubuntu-latest", "timeout-minutes: 10",
                         "persist-credentials: false",
                         "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
                         "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1", "3.11", "3.14",
                         "test_fictional_review_sequence*_1505.py"):
            self.assertIn(required, content)
        for forbidden in ("runs-on: self-hosted", "secrets.", "deploy:", "push:",
                          "pull_request_target:", "id-token: write",
                          "actions/checkout@v5", "actions/setup-python@v6", "write-all",
                          "contents: write", "sudo "):
            self.assertNotIn(forbidden, content)

    def test_all_committed_examples_are_only_fictional_and_bounded(self):
        patterns = (
            "fictional-sequence-1505-*.json",
            "fictional-pair-1505-*.json",
            "fictional-segments-1505-*.json",
            "fictional-anchor-1505-*.json",
            "fictional-links-1505-*.json",
        )
        examples = []
        for glob in patterns:
            examples.extend((ROOT / "docs/examples").glob(glob))
        self.assertEqual(len(examples), 10)
        for path in examples:
            payload = path.read_bytes()
            self.assertTrue(1 <= len(payload) <= 8192, path.name)
            self.assertTrue(payload.isascii(), path.name)
            self.assertNotIn(b"http", payload.lower())
            self.assertNotIn(b"@", payload)
            parsed = json.loads(payload)
            self.assertTrue(type(parsed) is dict)
            self.assertTrue(b"review-demo.example.test" in payload)
            self.assertFalse(b"example.com" in payload)


if __name__ == "__main__":
    unittest.main()
