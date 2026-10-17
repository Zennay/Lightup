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
    elif (
        isinstance(node, ast.FormattedValue)
        and node.format_spec is None
        and node.conversion in (-1, 115)
        and isinstance(node.value, ast.Constant)
        and type(node.value.value) is str
    ):
        # Exact, format-free literal f-string interpolation; never eval.
        text = _constant_text(node.value)
    elif isinstance(node, ast.JoinedStr):
        parts = [_constant_text(part) for part in node.values]
        text = "".join(parts) if all(part is not None for part in parts) else None
    else:
        return None
    return text if text is not None and len(text) <= 256 else None


def _fromlist_requests_reviewer(node: ast.AST | None) -> bool:
    """Only literal built-in list/tuple fromlists can load our package child."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("list", "tuple")
        and len(node.args) == 1
        and not node.keywords
    ):
        # Only immutable source syntax composed from literal built-in shapes.
        return _fromlist_requests_reviewer(node.args[0])
    return (
        isinstance(node, (ast.List, ast.Tuple))
        and any(_constant_text(item) == REVIEWER for item in node.elts)
    )


def _code_text(node: ast.AST) -> str | None:
    """Bounded static code text only, including literal UTF-8 bytes."""
    text = _constant_text(node)
    if text is not None:
        return text
    if isinstance(node, ast.Constant) and type(node.value) is bytes and len(node.value) <= 256:
        try:
            return node.value.decode("utf-8")
        except UnicodeError:
            return None
    return None


def references_review_module(source: str, *, _depth: int = 0) -> bool:
    """Detect imports and statically reconstructable calls, never eval code."""
    # Deep strings of nested exec must not slip through merely by depth.
    if _depth > 4:
        return True
    tree = ast.parse(source)
    # Track statically named imports, including aliases. This is deliberately
    # conservative: it does not execute alias binding or Python expressions.
    nodes = tuple(ast.walk(tree))
    importlib_names = {"importlib"}
    builtins_names = {"builtins"}
    # A bare local function named import_module is NOT an imported loader.
    # __import__ alone is always available as a Python builtin.
    import_module_names = {"__import__"}
    builtin_import_names = {"__import__"}
    code_loader_names = {"exec", "eval", "compile"}
    runpy_names = {"runpy"}
    pkgutil_names = {"pkgutil"}
    run_module_names: set[str] = set()
    resolve_name_names: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_names.add(alias.asname or alias.name)
                if alias.name == "builtins":
                    builtins_names.add(alias.asname or alias.name)
                if alias.name == "runpy":
                    runpy_names.add(alias.asname or alias.name)
                if alias.name == "pkgutil":
                    pkgutil_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if node.module == "importlib" and alias.name == "import_module":
                    import_module_names.add(alias.asname or alias.name)
                if node.module == "builtins" and alias.name == "__import__":
                    import_module_names.add(alias.asname or alias.name)
                    builtin_import_names.add(alias.asname or alias.name)
                if node.module == "builtins" and alias.name in ("exec", "eval", "compile"):
                    code_loader_names.add(alias.asname or alias.name)
                if node.module == "runpy" and alias.name == "run_module":
                    run_module_names.add(alias.asname or alias.name)
                if node.module == "pkgutil" and alias.name == "resolve_name":
                    resolve_name_names.add(alias.asname or alias.name)
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
        elif isinstance(node, ast.Call):
            called = node.func
            # No code execution: recursively PARSE short literal exec/eval/
            # compile source only. Nonliteral computed strings remain unproven.
            code_loader = (
                (isinstance(called, ast.Name) and called.id in code_loader_names)
                or (
                    isinstance(called, ast.Attribute)
                    and isinstance(called.value, ast.Name)
                    and called.value.id in builtins_names
                    and called.attr in ("exec", "eval", "compile")
                )
                or (
                    isinstance(called, ast.Call)
                    and isinstance(called.func, ast.Name)
                    and called.func.id == "getattr"
                    and len(called.args) == 2
                    and isinstance(called.args[0], ast.Name)
                    and called.args[0].id in builtins_names
                    and _constant_text(called.args[1]) in ("exec", "eval", "compile")
                )
            )
            if code_loader and node.args:
                inner_source = _code_text(node.args[0])
                if inner_source is not None:
                    try:
                        if references_review_module(inner_source, _depth=_depth + 1):
                            return True
                    except (SyntaxError, ValueError, RecursionError):
                        # Syntactically invalid static code cannot import.
                        pass
            # Named loader entrypoints may use name= or runpy's mod_name=.
            # Only fold literal strings; never execute application code.
            literal = (
                _constant_text(node.args[0]) if node.args else
                next((_constant_text(kw.value) for kw in node.keywords if kw.arg in ("name", "mod_name")), None)
            )
            if literal is None:
                continue
            called = node.func
            direct_import = isinstance(called, ast.Name) and called.id in (
                "__import__", *import_module_names, *run_module_names, *resolve_name_names,
            )
            qualified_import = (
                isinstance(called, ast.Attribute)
                and isinstance(called.value, ast.Name)
                and (
                    (called.attr == "import_module" and called.value.id in importlib_names)
                    or (called.attr == "__import__" and called.value.id in builtins_names)
                    or (called.attr == "run_module" and called.value.id in runpy_names)
                    or (called.attr == "resolve_name" and called.value.id in pkgutil_names)
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
                    or (called.args[0].id in runpy_names and _constant_text(called.args[1]) == "run_module")
                    or (called.args[0].id in pkgutil_names and _constant_text(called.args[1]) == "resolve_name")
                )
            )
            builtin_import = (
                (isinstance(called, ast.Name) and called.id in builtin_import_names)
                or (
                    isinstance(called, ast.Attribute)
                    and isinstance(called.value, ast.Name)
                    and called.attr == "__import__"
                    and called.value.id in builtins_names
                )
                or (
                    isinstance(called, ast.Call)
                    and isinstance(called.func, ast.Name)
                    and called.func.id == "getattr"
                    and len(called.args) == 2
                    and isinstance(called.args[0], ast.Name)
                    and called.args[0].id in builtins_names
                    and _constant_text(called.args[1]) == "__import__"
                )
            )
            if builtin_import and literal == "lightup":
                # The fourth positional argument is the CPython fromlist.
                arg = node.args[3] if len(node.args) >= 4 else None
                arg = next((kw.value for kw in node.keywords if kw.arg == "fromlist"), arg)
                if _fromlist_requests_reviewer(arg):
                    return True
            if direct_import or qualified_import or getattr_import:
                # pkgutil.resolve_name supports both dotted member access and
                # "module:symbol". The reviewer must not load through either.
                module_name = literal.split(":", 1)[0]
                parts = module_name.split(".")
                if REVIEWER in parts:
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

    def test_keyword_only_imports_are_detected(self):
        # importlib.import_module and __import__ accept a keyword "name".
        # A lexical check must not mistake these calls for unwired source.
        patterns = (
            "import importlib\nimportlib.import_module(name='lightup.scope_literal_control_review_20261016')",
            "import importlib as il\nil.import_module(name='lightup.scope_literal_control_review_20261016')",
            "from importlib import import_module as load\nload(name='lightup.scope_literal_control_review_20261016')",
            "import builtins as bi\nbi.__import__(name='lightup.scope_literal_control_review_20261016')",
            "from builtins import __import__ as loader\nloader(name='lightup.scope_literal_control_review_20261016')",
            "import importlib as il\ngetattr(il, 'import_module')(name='lightup.scope_literal_control_review_20261016')",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertTrue(references_review_module(source))

    def test_keyword_import_false_positive_controls(self):
        patterns = (
            "import importlib\nimportlib.import_module(name='lightup.scope')",
            "import importlib\nimportlib.import_module(package='lightup.scope_literal_control_review_20261016', name='lightup.scope')",
            "def import_module(*, name): return name\nimport_module(name='lightup.scope_literal_control_review_20261016')",
            "import importlib\nimportlib.import_module(name=variable)",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertFalse(references_review_module(source))

    def test_runpy_module_loader_forms_are_detected(self):
        # runpy executes module code and must not silently wire a reviewer.
        patterns = (
            "import runpy\nrunpy.run_module('lightup.scope_literal_control_review_20261016')",
            "import runpy as rp\nrp.run_module(mod_name='lightup.scope_literal_control_review_20261016')",
            "from runpy import run_module as execute\nexecute('lightup.scope_literal_control_review_20261016')",
            "import runpy as rp\ngetattr(rp, 'run_module')(mod_name='lightup.scope_literal_control_review_20261016')",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertTrue(references_review_module(source))

    def test_pkgutil_symbol_load_forms_are_detected(self):
        # resolve_name can import before walking the member name.
        patterns = (
            "import pkgutil\npkgutil.resolve_name('lightup.scope_literal_control_review_20261016:review_literals')",
            "import pkgutil as pk\npk.resolve_name(name='lightup.scope_literal_control_review_20261016.review_literals')",
            "from pkgutil import resolve_name as look\nlook('lightup.scope_literal_control_review_20261016:review_literals')",
            "import pkgutil as pk\ngetattr(pk, 'resolve_name')(name='lightup.scope_literal_control_review_20261016:review_literals')",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertTrue(references_review_module(source))
        controls = (
            "import pkgutil\npkgutil.resolve_name('lightup.scope:other')",
            "import runpy\nrunpy.run_module('lightup.scope')",
            "import pkgutil\npkgutil.resolve_name(name=dynamic_name)",
            "def run_module(*, mod_name): return mod_name\nrun_module(mod_name='lightup.scope_literal_control_review_20261016')",
        )
        for source in controls:
            with self.subTest(source=source):
                self.assertFalse(references_review_module(source))

    def test_builtin_fromlist_package_imports(self):
        # __import__("lightup", fromlist=(reviewer,)) asks CPython to
        # import a previously missing package child as a side effect.
        patterns = (
            "__import__('lightup', fromlist=['scope_literal_control_review_20261016'])",
            "__import__('lightup', fromlist=('scope_literal_control_review_20261016',))",
            "__import__('lightup', None, None, ['scope_literal_control_review_20261016'])",
            "import builtins as bi\nbi.__import__('lightup', fromlist=['scope_literal_control_review_20261016'])",
            "from builtins import __import__ as load\nload('lightup', fromlist=['scope_literal_control_review_20261016'])",
            "import builtins as bi\ngetattr(bi,'__import__')('lightup', fromlist=['scope_literal_control_review_20261016'])",
            "__import__('lightup', fromlist=['scope_literal_' + 'control_review_20261016'])",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertTrue(references_review_module(source))

    def test_builtin_fromlist_unrelated_controls(self):
        patterns = (
            "__import__('other', fromlist=['scope_literal_control_review_20261016'])",
            "__import__('lightup', fromlist=['other_module'])",
            "__import__('lightup', fromlist=dynamic_items)",
            "import importlib\nimportlib.import_module('lightup', package='scope_literal_control_review_20261016')",
            "__import__('lightup', fromlist=['scope_literal_control_review_20261016_suffix'])",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertFalse(references_review_module(source))

    def test_literal_exec_eval_compile_are_detected(self):
        cases = (
            "exec(\"import lightup.scope_literal_control_review_20261016\")",
            "eval(\"__import__('lightup.scope_literal_control_review_20261016')\")",
            "compile(\"from lightup import scope_literal_control_review_20261016\", \"dummy\", \"exec\")",
            "exec(b'import lightup.scope_literal_control_review_20261016')",
            "exec(\"from lightup import \" + \"scope_literal_control_review_20261016\")",
            "exec('exec(\"import lightup.scope_literal_control_review_20261016\")')",
            "import builtins as b\ngetattr(b, \"exec\")(\"import lightup.scope_literal_control_review_20261016\")",
            "from builtins import exec as runner\nrunner(\"from lightup import scope_literal_control_review_20261016\")",
        )
        for code in cases:
            with self.subTest(code=code):
                self.assertTrue(references_review_module(code))

    def test_literal_eval_negative_controls(self):
        cases = (
            "exec(\"import lightup.scope\")",
            "eval(\"'scope_literal_control_review_20261016'\")",
            "compile(\"x=1\", \"dummy\", \"exec\")",
            "print('exec(\"import lightup.scope_literal_control_review_20261016\")')",
        )
        for code in cases:
            with self.subTest(code=code):
                self.assertFalse(references_review_module(code))

    def test_static_fromlist_constructors_and_literal_fstrings(self):
        patterns = (
            "__import__('lightup', fromlist=tuple(['scope_literal_control_review_20261016']))",
            "__import__('lightup', fromlist=list(('scope_literal_control_review_20261016',)))",
            "__import__('lightup', fromlist=[f\"{'scope_literal_'}control_review_20261016\"])",
            "import importlib\nimportlib.import_module(f\"lightup.{'scope_literal_control_review_20261016'}\")",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertTrue(references_review_module(source))

    def test_static_fromlist_constructors_negative_controls(self):
        patterns = (
            "__import__('lightup', fromlist=tuple(['other_module']))",
            "__import__('other', fromlist=list(('scope_literal_control_review_20261016',)))",
            "__import__('lightup', fromlist=tuple(dynamic))",
            "import importlib\nimportlib.import_module(f\"lightup.{dynamic}\")",
        )
        for source in patterns:
            with self.subTest(source=source):
                self.assertFalse(references_review_module(source))

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
