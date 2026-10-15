"""HOLD-only offline original-source RED receipt, LightUp issue #1147.

Invoke explicitly from repo root:
    python -m scripts.scope_1147_red_receipt_cli

No arguments or customer records. Reads installed local Python code, exercises
only fictional ANALYSIS-only cases and disposable SQLite, and NEVER returns
authorization, dispatch, merge, deploy or scan permission.

Exit 2 = precise known original-source RED confirmed (still HOLD).
Exit 3 = unknown/invalid receipt (HOLD). Exit 0 is forbidden.
"""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch


def _receipt(reason: str) -> dict[str, object]:
    return {
        "status": "HOLD",
        "issue": "1147",
        "reason": reason,
        "can_authorize": False,
        "can_dispatch": False,
        "can_merge": False,
        "can_deploy": False,
        "can_scan": False,
        "can_release": False,
    }


def main(argv: list[str] | None = None) -> int:
    # Always emit exactly one privacy-minimal JSON line, including on errors.
    arguments = list(sys.argv[1:] if argv is None else argv)
    result = _receipt("UNVERIFIED")
    exit_code = 3
    if arguments:
        result["reason"] = "INVALID_INVOCATION"
    else:
        # This offline diagnostic can also be called inside a unit-test runner.
        # Never leave import paths or bytecode settings changed in the caller,
        # whether the receipt is confirmed or an internal error is suppressed.
        original_path = list(sys.path)
        original_bytecode = sys.dont_write_bytecode
        try:
            root = Path(__file__).resolve().parents[1]
            sys.dont_write_bytecode = True
            sys.path.insert(0, str(root / "src"))
            sys.path.insert(0, str(root / "tests"))

            def block_network(*_args, **_kwargs):
                raise AssertionError("offline diagnostics prohibit socket/DNS access")

            # Guard imports and entire reference execution. The individual
            # tests also separately fail-hard on these three entrypoints.
            with (
                patch.object(socket, "socket", side_effect=block_network),
                patch.object(socket, "create_connection", side_effect=block_network),
                patch.object(socket, "getaddrinfo", side_effect=block_network),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                from test_scope_1147_duplicate_key_installed_matrix_20261015 import (
                    DuplicateArgumentKeysInstalledSource1147,
                )
                from test_scope_1147_expected_red_integrity_20261015 import (
                    verify_source_red_receipt,
                )
                suite = unittest.defaultTestLoader.loadTestsFromTestCase(
                    DuplicateArgumentKeysInstalledSource1147
                )
                test_result = unittest.TestResult()
                suite.run(test_result)
                verify_source_red_receipt(test_result)
            result = _receipt("KNOWN_SOURCE_RED_CONFIRMED")
            exit_code = 2
        except BaseException:
            # Never echo exception text (which could carry future metadata),
            # never convert unknown crashes into successful proof.
            result = _receipt("UNVERIFIED")
            exit_code = 3
        finally:
            sys.path[:] = original_path
            sys.dont_write_bytecode = original_bytecode
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
