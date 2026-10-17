"""AST-only proof that the inert fictional reviewer stays out of runtime imports.

No application imports, filesystem writes, network calls or permissions.
Computed reflection/eval is not proven safe by a static lexical guard.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REVIEWER = "scope_literal_control_review_20261016"
SOURCE_DIR = ROOT / "src" / "lightup"
SCRIPT_DIR = ROOT / "scripts"
OWNED_HELPERS = frozenset({
    "review_scope_literal_controls_20261016.py",
    "check_scope_literal_suite_20261016.py",
    "check_scope_literal_branch_20261016.py",
})


def _constant_text(node: ast.AST) -> str | None:
    """Bounded AST-only constant folding; never eval or import anything."""
    if isinstance(node, ast.Constant) and type(node.value) is str:
        text = node.value
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_text(node.left)
        right = _constant_text(node.right)
        text = left + right if left is not None and right is not None else None
    elif isinstance(node, ast.JoinedStr):
        parts = [_constant_text(part) for part in node.values]
        text = "".join(parts) if all(part is not None for part in parts) else None
    else:
        return None
    return text if text is not None and len(text) <= 256 else None


def references_review_module(source: str) -> bool:
    """Detect imports and statically reconstructable calls, never eval code."""
    tree = ast.parse(source)
    # Track statically named imports, including aliases. This is deliberately
    # conservative: it does not execute alias binding or Python expressions.
    nodes = tuple(ast.walk(tree))
    importlib_names = {"importlib"}
    builtins_names = {"builtins"}
    import_module_names = {"import_module", "__import__"}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_names.add(alias.asname or alias.name)
                if alias.name == "builtins":
                    builtins_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if node.module == "importlib" and alias.name == "import_module":
                    import_module_names.add(alias.asname or alias.name)
                if node.module == "builtins" and alias.name == "__import__":
                    import_module_names.add(alias.asname or alias.name)
    for node in nodes:
        if isinstance(node, ast.Import):
            if any(name.name.split(".")[-1] == REVIEWER for name in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[-1] == REVIEWER:
                return True
            # Both "from lightup import reviewer" and "from . import reviewer"
            # can promote the module despite the module field not containing it.
            if any(name.name == REVIEWER for name in node.names):
                return True
        elif isinstance(node, ast.Call) and node.args:
            literal = _constant_text(node.args[0])
            if literal is None:
                continue
            called = node.func
            direct_import = isinstance(called, ast.Name) and called.id in (
                "__import__", *import_module_names,
            )
            qualified_import = (
                isinstance(called, ast.Attribute)
                and isinstance(called.value, ast.Name)
                and (
                    (called.attr == "import_module" and called.value.id in importlib_names)
                    or (called.attr == "__import__" and called.value.id in builtins_names)
                )
            )
            getattr_import = (
                isinstance(called, ast.Call)
                and isinstance(called.func, ast.Name)
                and called.func.id == "getattr"
                and len(called.args) == 2
                and isinstance(called.args[0], ast.Name)
                and (
                    (called.args[0].id in importlib_names and _constant_text(called.args[1]) == "import_module")
                    or (called.args[0].id in builtins_names and _constant_text(called.args[1]) == "__import__")
                )
            )
            if (direct_import or qualified_import or getattr_import) and literal.split(".")[-1] == REVIEWER:
                return True
    return False


class RuntimeIsolationStaticTests(unittest.TestCase):
    def test_all_production_modules_stay_unwired(self):
        files = sorted(SOURCE_DIR.rglob("*.py"))
        self.assertGreater(len(files), 30)
        with patch("socket.socket", side_effect=AssertionError("offline AST only")):
            for path in files:
                if path.stem == REVIEWER:
                    continue
                with self.subTest(path=str(path.relative_to(ROOT))):
                    self.assertFalse(
                        references_review_module(path.read_text(encoding="utf-8")),
                        "Inert reviewer imported in application source",
                    )

    def test_no_nonowned_application_script_imports_reviewer(self):
        scripts = sorted(SCRIPT_DIR.rglob("*.py"))
        self.assertGreaterEqual(len(scripts), len(OWNED_HELPERS))
        self.assertEqual(
            {path.name for path in scripts if path.name in OWNED_HELPERS},
            OWNED_HELPERS,
        )
        for path in scripts:
            if path.name in OWNED_HELPERS:
                continue
            with self.subTest(script=path.name):
                self.assertFalse(
                    references_review_module(path.read_text(encoding="utf-8")),
                    "Other script has started importing inert scope reviewer",
                )

    def test_catches_every_literal_import_shape(self):
        patterns = (
            "import lightup.scope_literal_control_review_20261016",
            "import lightup.scope_literal_control_review_20261016 as imported",
            "from lightup.scope_literal_control_review_20261016 import review_literals",
            "from .scope_literal_control_review_20261016 import review_literals",
            "from lightup import scope_literal_control_review_20261016",
            "from . import scope_literal_control_review_20261016",
            "from importlib import import_module\nimport_module('lightup.scope_literal_control_review_20261016')",
            "import importlib\nimportlib.import_module('lightup.scope_literal_control_review_20261016')",
            "__import__('lightup.scope_literal_control_review_20261016')",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertTrue(references_review_module(source))

    def test_static_string_construction_is_detected(self):
        patterns = (
            "import importlib\nimportlib.import_module('lightup.' + 'scope_literal_control_review_20261016')",
            "import importlib\nimportlib.import_module(f'lightup.scope_literal_control_review_20261016')",
            "import importlib\ngetattr(importlib, 'import_module')('lightup.scope_literal_control_review_20261016')",
            "__import__('lightup.' + 'scope_literal_' + 'control_review_20261016')",
            "from importlib import import_module\nimport_module(f'lightup.scope_literal_control_review_20261016')",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertTrue(references_review_module(source))

    def test_importlib_aliases_cannot_bypass_static_guard(self):
        patterns = (
            "import importlib as il\nil.import_module('lightup.scope_literal_control_review_20261016')",
            "from importlib import import_module as load\nload('lightup.scope_literal_control_review_20261016')",
            "from importlib import import_module as load\nload('lightup.' + 'scope_literal_control_review_20261016')",
            "import importlib as il\ngetattr(il, 'import_module')('lightup.scope_literal_control_review_20261016')",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertTrue(references_review_module(source))

    def test_builtin_import_aliases_cannot_bypass_static_guard(self):
        patterns = (
            "import builtins\nbuiltins.__import__('lightup.scope_literal_control_review_20261016')",
            "import builtins as bi\nbi.__import__('lightup.scope_literal_control_review_20261016')",
            "from builtins import __import__ as loader\nloader('lightup.scope_literal_control_review_20261016')",
            "import builtins as bi\ngetattr(bi, '__import__')('lightup.scope_literal_control_review_20261016')",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertTrue(references_review_module(source))

    def test_does_not_flag_unrelated_imports_or_comments(self):
        samples = (
            "import lightup.scope\nfrom lightup import scope",
            "# import lightup.scope_literal_control_review_20261016",
            "message = 'scope_literal_control_review_20261016'",
            "import importlib\nimportlib.import_module('lightup.scope')",
            "from . import activation",
            "from lightup.other import review_literals",
            "def f():\n    return 'lightup.scope_literal_control_review_20261016'",
        )
        for source in samples:
            with self.subTest(source=source):
                self.assertFalse(references_review_module(source))

    def test_reflection_limit_is_documented_not_claimed_proven(self):
        # Built-up strings and reflection are deliberately OUTSIDE the
        # claimed AST-literal threat model, not a false assertion of safety.
        code = (
            "module = 'scope_literal_' + 'control_review_20261016'\n"
            "__import__('lightup.' + module)"
        )
        self.assertFalse(references_review_module(code))


if __name__ == "__main__":
    unittest.main()
