"""#1511 independent AST/source and hosted runner isolation regression.

Static checks only; no claim to prove reflective/runtime import behavior or
cryptographic provenance. Production source must remain unwired from this
fictional non-authorizing reference helper.
"""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = "fictional_lab_capability_review_1511"
CLI = "fictional_lab_capability_cli_1511"
OWNED = {
    Path("src/lightup/fictional_lab_capability_review_1511.py"),
    Path("src/lightup/fictional_lab_capability_batch_1511.py"),
    Path("scripts/fictional_lab_capability_cli_1511.py"),
    Path("scripts/fictional_lab_capability_batch_cli_1511.py"),
    Path("tests/test_fictional_lab_capability_review_1511.py"),
    Path("tests/test_fictional_lab_capability_cli_1511.py"),
    Path("tests/test_fictional_lab_capability_batch_1511.py"),
    Path("tests/test_fictional_lab_capability_batch_cli_1511.py"),
    Path("tests/test_fictional_lab_capability_cli_process_boundary_1511.py"),
    Path("tests/test_fictional_lab_capability_registry_compat_1511.py"),
    Path("tests/test_fictional_lab_capability_sealing_1511.py"),
    Path("tests/test_fictional_lab_capability_transition_1511.py"),
    Path("tests/test_fictional_lab_capability_streaming_1511.py"),
    Path("tests/test_fictional_lab_capability_isolation_1511.py"),
    Path("docs/scope-lab-capability-identity-1511.md"),
    Path(".github/workflows/scope-lab-capability-review-1511.yml"),
}


def _parsed(path):
    return ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=str(path))


class FictionalLabCapabilityIsolation1511Tests(unittest.TestCase):
    def test_no_original_runtime_python_module_directly_imports_new_helper(self):
        for path in sorted((ROOT / "src" / "lightup").rglob("*.py")):
            relative = path.relative_to(ROOT)
            if relative in OWNED:
                continue
            with self.subTest(path=str(relative)):
                tree = _parsed(relative)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertNotIn(MODULE, alias.name.split("."))
                            self.assertNotIn(CLI, alias.name.split("."))
                    if isinstance(node, ast.ImportFrom):
                        self.assertNotIn(MODULE, (node.module or "").split("."))
                        self.assertNotIn(CLI, (node.module or "").split("."))
                        self.assertFalse(any(alias.name in (MODULE, CLI) for alias in node.names))

    def test_no_literal_dynamic_source_imports_of_fictional_module(self):
        for path in sorted((ROOT / "src" / "lightup").rglob("*.py")):
            relative = path.relative_to(ROOT)
            if relative in OWNED:
                continue
            with self.subTest(path=str(relative)):
                tree = _parsed(relative)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
                        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
                        if name not in ("__import__", "import_module"):
                            continue
                        for arg in node.args[:1]:
                            if isinstance(arg, ast.Constant) and type(arg.value) is str:
                                self.assertNotIn(MODULE, arg.value)
                                self.assertNotIn(CLI, arg.value)

    def test_cli_only_imports_pure_fictional_module_from_lightup(self):
        tree = _parsed(Path("scripts/fictional_lab_capability_cli_1511.py"))
        imports = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertEqual([name for name in imports if name.startswith("lightup.")],
                         ["lightup." + MODULE])
        names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        for forbidden in ("socket", "requests", "subprocess", "http.client", "urllib.request"):
            self.assertNotIn(forbidden, names)

    def test_batch_helper_and_cli_are_unwired_from_original_source(self):
        targets = ("fictional_lab_capability_batch_1511",
                   "fictional_lab_capability_batch_cli_1511")
        for path in sorted((ROOT / "src/lightup").rglob("*.py")):
            rel = path.relative_to(ROOT)
            if rel in OWNED:
                continue
            tree = _parsed(rel)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertTrue(all(token not in alias.name.split(".") for token in targets))
                if isinstance(node, ast.ImportFrom):
                    self.assertTrue(all(token not in (node.module or "").split(".") for token in targets))
                if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
                    name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
                    if name in ("__import__", "import_module") and node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.Constant) and type(arg.value) is str:
                            self.assertTrue(all(token not in arg.value for token in targets))

    def test_batch_cli_has_no_target_or_network_imports(self):
        tree = _parsed(Path("scripts/fictional_lab_capability_batch_cli_1511.py"))
        imported = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertEqual([name for name in imported if name.startswith("lightup.")],
                         ["lightup.fictional_lab_capability_batch_1511"])
        names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        for forbidden in ("socket", "requests", "subprocess", "http.client", "urllib.request"):
            self.assertNotIn(forbidden, names)

    def test_fictional_helper_has_no_network_or_file_io_imports(self):
        tree = _parsed(Path("src/lightup/fictional_lab_capability_review_1511.py"))
        names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        for forbidden in ("socket", "os", "pathlib", "requests", "subprocess"):
            self.assertNotIn(forbidden, names)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"open", "eval", "exec", "__import__"})

    def test_workflow_is_isolated_readonly_and_pinned(self):
        wf = (ROOT / ".github/workflows/scope-lab-capability-review-1511.yml").read_text()
        self.assertIn("permissions:\n  contents: read\n", wf)
        self.assertIn("persist-credentials: false", wf)
        self.assertIn("timeout-minutes: 10", wf)
        self.assertIn("runs-on: ubuntu-latest", wf)
        self.assertIn("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", wf)
        self.assertIn("actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1", wf)
        self.assertIn("['3.11', '3.14']", wf)
        self.assertIn("test_fictional_lab_capability*_1511.py", wf)
        for file in OWNED:
            if file.suffix == ".py" and file.parts[0] in ("src", "scripts", "tests"):
                self.assertIn(str(file), wf, f"workflow PR filter missing own file: {file}")
        for forbidden in ("pull_request_target:", "push:", "write-all", "self-hosted", "secrets.", "curl ", "wget ", "pip install"):
            self.assertNotIn(forbidden, wf)

    def test_paths_are_exclusively_owned_and_never_prod_runtime(self):
        for rel in OWNED:
            self.assertTrue((ROOT / rel).is_file(), f"required file missing: {rel}")
            self.assertNotIn(str(rel), (
                "src/lightup/activation.py", "src/lightup/scope.py",
                "src/lightup/models.py", "src/lightup/domain.py",
            ))


if __name__ == "__main__":
    unittest.main()
