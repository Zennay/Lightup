"""Issue #1535: warning-free original renderer import on Python 3.11/3.14.

Offline-only: no targets, no grants and no handler invocation.
Existing native I/O fleet tests independently prove the original tripwire
stays enabled; these tests never patch its forbidden() callback.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import unittest
import warnings

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/lightup/capability_registry_history_report.py"


class ScopeRegistrySyntaxWarningTests(unittest.TestCase):
    def test_renderer_source_compiles_when_escape_warnings_are_errors(self):
        source = SOURCE.read_text(encoding="utf-8")
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            warnings.simplefilter("error", DeprecationWarning)
            code = compile(source, str(SOURCE), "exec", dont_inherit=True)
        self.assertIsNotNone(code)

    def test_renderer_source_imports_in_isolated_python_with_warning_error(self):
        code = (
            "import sys; sys.path.insert(0, 'src'); "
            "import lightup.capability_registry_history_report; "
            "print('offline-renderer-import-ok')"
        )
        child = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-W", "error::SyntaxWarning",
             "-W", "error::DeprecationWarning", "-c", code],
            cwd=ROOT, input=b"", capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stdout, b"offline-renderer-import-ok\n")
        self.assertEqual(child.stderr, b"")

    def test_source_diff_has_no_guard_disable_or_execution_hook(self):
        # Independent of source-owner tool admission and gate logic.
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("render_capability_registry_history_markdown", source)
        self.assertIn("review_capability_registry_history", source)
        for forbidden_marker in ("_io.open =", "socket.socket =", "subprocess.Popen =",
                                 "forbidden = lambda", "os._exit ="):
            self.assertNotIn(forbidden_marker, source)


if __name__ == "__main__":
    unittest.main()
