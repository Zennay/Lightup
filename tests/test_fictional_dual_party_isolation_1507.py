"""Installed-source regression guard for #1507 draft-only reviewer isolation.

An AST allowlist is a *limited* source-change tripwire, not a runtime security
sandbox or evidence of cryptographic provenance. No runtime imports executed.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "lightup"
NAME = "fictional_dual_party_review_1507"
CLI = "fictional_dual_party_cli_1507"
WORKFLOW = ROOT / ".github" / "workflows" / "scope-fictional-dual-party-review-1507.yml"


class ReviewerSourceIsolationTests(unittest.TestCase):
    def test_existing_runtime_python_cannot_directly_import_reviewer(self):
        reviewed = 0
        for filename in PACKAGE.rglob("*.py"):
            if filename.stem in (NAME, CLI):
                continue
            tree = ast.parse(filename.read_text(encoding="utf-8"), filename=str(filename))
            reviewed += 1
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for target in node.names:
                        self.assertNotIn(NAME, target.name, str(filename))
                        self.assertNotIn(CLI, target.name, str(filename))
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn(NAME, node.module or "", str(filename))
                    self.assertNotIn(CLI, node.module or "", str(filename))
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                        literal = node.args[0] if node.args else None
                        self.assertFalse(isinstance(literal, ast.Constant) and
                                         isinstance(literal.value, str) and
                                         (NAME in literal.value or CLI in literal.value))
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
                        literal = node.args[0] if node.args else None
                        self.assertFalse(isinstance(literal, ast.Constant) and
                                         isinstance(literal.value, str) and
                                         (NAME in literal.value or CLI in literal.value))
        self.assertGreater(reviewed, 20)

    def test_optin_source_only_imports_small_stdlib_allowlist(self):
        allowed = {"__future__", "datetime", "dataclasses", "re", "json", "sys",
                   "lightup.fictional_dual_party_review_1507"}
        for stem in (NAME, CLI):
            tree = ast.parse((PACKAGE / (stem + ".py")).read_text(encoding="utf-8"))
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(item.name for item in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.add(node.module or "")
            self.assertTrue(imports <= allowed, imports - allowed)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertFalse(any("socket" in x.name or "subprocess" in x.name
                                         or "sqlite" in x.name for x in node.names))

    def test_dedicated_workflow_is_unprivileged_and_hosted_only(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("contents: read", source)
        self.assertIn("persist-credentials: false", source)
        self.assertIn("runs-on: ubuntu-latest", source)
        self.assertIn("timeout-minutes: 10", source)
        self.assertNotIn("self-hosted", source)
        self.assertNotIn("pull_request_target", source)
        self.assertIn("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", source)
        self.assertIn("actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1", source)

    def test_documented_review_only_is_never_user_consent(self):
        source = (ROOT / "docs" / "scope-fictional-dual-party-review-1507.md").read_text()
        for marker in ("DRAFT/HOLD", "NOT AUTHORIZED", "consent_verified=False",
                       "registered permanent", "explicit human GO"):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
