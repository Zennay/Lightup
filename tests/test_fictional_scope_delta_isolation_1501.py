"""Static non-binding canaries for fictional #1501 reviewer isolation.

These checks are restricted syntactic evidence, NOT a runtime security proof.
Other owners' production source and workflow files remain unchanged.
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "lightup"
OWNED = frozenset({
    "fictional_scope_delta_review_1501.py",
    "fictional_scope_delta_cli_1501.py",
})
MODULES = frozenset({
    "fictional_scope_delta_review_1501",
    "fictional_scope_delta_cli_1501",
})
FORBIDDEN = frozenset({
    "socket", "sqlite3", "subprocess", "os", "pathlib",
    "requests", "http", "urllib", "ftplib", "ctypes", "multiprocessing",
    "lightup.scope", "lightup.activation", "lightup.execution_policy",
    "lightup.domain", "lightup.engagements",
})


def _imports_owned_module(tree: ast.AST) -> bool:
    """Inspect both module path AND bound symbols (relative import aliases)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(
                any(owned in alias.name for owned in MODULES)
                for alias in node.names
            ):
                return True
        elif isinstance(node, ast.ImportFrom):
            if any(owned in (node.module or "") for owned in MODULES):
                return True
            if any(
                any(owned in alias.name for owned in MODULES)
                for alias in node.names
            ):
                return True
    return False


class FictionalScopeIsolationTests(TestCase):
    def test_existing_production_sources_do_not_statically_import_new_review_code(self):
        self.assertEqual(len(OWNED), 2)
        paths = tuple(PACKAGE.glob("*.py"))
        self.assertGreater(len(paths), 5)
        for path in paths:
            if path.name in OWNED:
                continue
            with self.subTest(file=path.name):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
                self.assertFalse(
                    _imports_owned_module(tree),
                    "Original source unexpectedly imports synthetic reviewer",
                )

    def test_direct_import_detection_guards_relative_alias_syntax(self):
        should_detect = (
            "from . import fictional_scope_delta_review_1501",
            "from . import fictional_scope_delta_cli_1501 as synthetic",
            "from lightup import fictional_scope_delta_review_1501",
            "from .fictional_scope_delta_review_1501 import review_fictional_scope_delta",
            "import lightup.fictional_scope_delta_review_1501",
            "import lightup.fictional_scope_delta_cli_1501 as harmless_alias",
        )
        for source in should_detect:
            with self.subTest(source=source):
                self.assertTrue(_imports_owned_module(ast.parse(source)))
        for source in ("from . import scope", "import json", "from .models import Target"):
            with self.subTest(source=source):
                self.assertFalse(_imports_owned_module(ast.parse(source)))

    def test_dedicated_ci_never_targets_authorized_execution_or_self_hosted(self):
        workflow = ROOT / ".github" / "workflows" / "scope-fictional-delta-1501.yml"
        content = workflow.read_text(encoding="utf-8")
        self.assertIn("  pull_request:", content)
        self.assertIn("  workflow_dispatch:", content)
        self.assertNotIn("  push:", content)
        self.assertIn("runs-on: ubuntu-latest", content)
        self.assertNotIn("runs-on: self-hosted", content)
        self.assertIn("permissions:\n  contents: read", content)
        self.assertIn("cancel-in-progress: true", content)
        self.assertIn("lightup-1501-synthetic-", content)
        self.assertIn("docs/examples/scope-fictional-*-1501.json", content)
        self.assertIn("test_fictional_scope_delta*_1501.py", content)
        self.assertNotIn("workflow_call:", content)
        self.assertNotIn("schedule:", content)
        self.assertNotIn("deployment:", content)

    def test_review_modules_have_no_active_source_or_external_io_imports(self):
        for name in OWNED:
            with self.subTest(file=name):
                path = PACKAGE / name
                self.assertTrue(path.is_file())
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=name)
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        module = (node.module or "").lstrip(".")
                        self.assertNotIn(module.split(".")[0], FORBIDDEN)
                        self.assertNotIn(module, FORBIDDEN)
                        self.assertFalse(
                            any(module == f"lightup.{x}" for x in (
                                "scope", "activation", "execution_policy", "domain",
                                "engagements", "models",
                            ))
                        )
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertNotIn(alias.name.split(".")[0], FORBIDDEN)
                            self.assertNotIn(alias.name, FORBIDDEN)

    def test_review_modules_never_expose_runtime_permission_symbols(self):
        forbidden = {
            "ExecutionPermit", "ScopePolicy", "ActivationGate", "ExecutionPolicy",
            "AuthorizationGrant", "Authorization", "ToolExecutor",
        }
        for name in OWNED:
            with self.subTest(file=name):
                tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
                assigned = set()
                for node in ast.walk(tree):
                    if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                        assigned.add(node.name)
                    if isinstance(node, ast.ImportFrom):
                        assigned.update(alias.asname or alias.name for alias in node.names)
                    if isinstance(node, ast.Import):
                        assigned.update(alias.asname or alias.name for alias in node.names)
                self.assertFalse(forbidden & assigned)

    def test_review_helpers_do_not_use_dynamic_code_or_process_primitives(self):
        forbidden_names = {"eval", "exec", "compile", "__import__", "open", "system", "popen"}
        for name in OWNED:
            with self.subTest(file=name):
                tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        callee = node.func
                        if isinstance(callee, ast.Name):
                            self.assertNotIn(callee.id, forbidden_names)
                        elif isinstance(callee, ast.Attribute):
                            # `re.compile` builds a safe regex, not Python
                            # bytecode. Don't turn static review into a false
                            # production blocker for regular expressions.
                            safe_regex = (
                                callee.attr == "compile"
                                and isinstance(callee.value, ast.Name)
                                and callee.value.id == "re"
                            )
                            if not safe_regex:
                                self.assertNotIn(callee.attr, forbidden_names)
