"""W56 synthetic-only CLI adapter failure boundary regression (#1221).

All adapters run in-process on invented data. This never executes a real Markdown
engine, tenant export, target scan, browser DOM or production process.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from html import escape
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.markdown_html_downstream_contract_w51 import main

_PRIVATE = "SYNTHETIC-W51-METADATA-PRIVATE"


class DownstreamAdapterFailureBoundaryW56(unittest.TestCase):
    def _call(self, adapter) -> tuple[int, str, str]:
        stderr = io.StringIO()
        stdout = io.StringIO()
        with patch(
            "tests.markdown_html_downstream_contract_w51.importlib.import_module",
            return_value=SimpleNamespace(render=adapter),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(["--renderer", "synthetic_w56:render"])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_runtime_adapter_failures_are_classified_not_raised(self) -> None:
        errors = (
            RuntimeError("synthetic failure"),
            OSError("synthetic IO fault"),
            TimeoutError("synthetic timeout"),
            LookupError("synthetic missing data"),
            ArithmeticError("synthetic arithmetic fault"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                def broken(_markdown: str, *, _error: Exception = error) -> str:
                    raise _error

                code, out, err = self._call(broken)
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn("REJECTED/INCONCLUSIVE", err)
                self.assertIn(type(error).__name__, err)
                self.assertNotIn(str(error), err)
                self.assertNotIn("Traceback", err)

    def test_exception_text_cannot_expose_invented_private_marker(self) -> None:
        def broken(_markdown: str) -> str:
            raise RuntimeError("failure contains " + _PRIVATE + " and private path")

        code, out, err = self._call(broken)
        self.assertEqual(code, 1)
        self.assertNotIn(_PRIVATE, out + err)
        self.assertNotIn("private path", out + err)
        self.assertNotIn("Traceback", out + err)

    def test_safe_escaped_control_still_passes_as_synthetic_only(self) -> None:
        code, out, err = self._call(
            lambda markdown: "<pre>" + escape(markdown, quote=True) + "</pre>"
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("SYNTHETIC-ONLY", out)
        self.assertIn("NOT installed", out)
        self.assertNotIn(_PRIVATE, out)

    def test_explicit_bad_return_still_denies_without_html_output(self) -> None:
        code, out, err = self._call(lambda _markdown: None)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("ValueError", err)

    def test_missing_adapter_is_inconclusive_not_pass(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main([])
        self.assertEqual(code, 2)
        self.assertIn("INCONCLUSIVE", stderr.getvalue())
        self.assertNotIn("PASS", stderr.getvalue())

    def test_process_interrupt_is_not_swallowed(self) -> None:
        def interrupted(_markdown: str) -> str:
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self._call(interrupted)


if __name__ == "__main__":
    unittest.main()
