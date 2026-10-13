"""Real subprocess + disposable SQLite tests for the #1307 synthetic CLI.

All tests use only internal offline-check IDs; no active target or network.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lightup.offline_executor_batch_cli_optin import _preview


class OfflineSyntheticCli1307(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lightup-cli-1307-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _run(self, data: bytes, *extra: str):
        path = self.root / "plan.json"
        path.write_bytes(data)
        return subprocess.run(
            [
                sys.executable,
                "-m", "lightup.offline_executor_batch_cli_optin",
                "--input", str(path), *extra,
            ],
            capture_output=True,
            check=False,
            timeout=15,
        )

    def _json(self, data: object):
        return self._run(json.dumps(data).encode("utf-8"))

    def _assert_denied(self, process):
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, b"")
        self.assertEqual(process.stderr, b"synthetic offline preview denied\n")

    def test_one_canonical_tool_returns_only_non_authorizing_receipt(self):
        result = self._json({"version": 1, "tools": ["offline-check-001"]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(json.loads(result.stdout), {
            "status": "reviewed",
            "tools_reviewed": 1,
            "permit_issued": False,
            "execution_enabled": False,
            "authorization_verified": False,
        })
        self.assertNotIn(b"offline-check-001", result.stdout)

    def test_checked_in_example_plan_runs_without_echo_or_permission(self):
        example = Path(__file__).resolve().parents[1] / "examples" / "offline_executor_plan_1307.json"
        self.assertTrue(example.is_file())
        p = subprocess.run(
            [sys.executable, "-m", "lightup.offline_executor_batch_cli_optin",
             "--input", str(example)],
            capture_output=True, check=False, timeout=15,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        parsed = json.loads(p.stdout)
        self.assertEqual(parsed["tools_reviewed"], 2)
        self.assertFalse(parsed["permit_issued"])
        self.assertFalse(parsed["execution_enabled"])
        self.assertFalse(parsed["authorization_verified"])
        self.assertNotIn(b"offline-check", p.stdout)

    def test_two_tools_reviewed_without_disclosing_identifiers(self):
        result = self._json({
            "version": 1,
            "tools": ["offline-check-002", "offline-check-064"],
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["tools_reviewed"], 2)
        self.assertNotIn(b"offline-check-", result.stdout)

    def test_all_sixty_four_unique_synthetic_tools_accepted(self):
        result = self._json({
            "version": 1,
            "tools": [f"offline-check-{n:03d}" for n in range(1, 65)],
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["tools_reviewed"], 64)

    def test_empty_list_and_too_many_tools_denied_atomically(self):
        for tools in (
            [],
            [f"offline-check-{n:03d}" for n in range(1, 65)] + ["offline-check-001"],
        ):
            with self.subTest(size=len(tools)):
                self._assert_denied(self._json({"version": 1, "tools": tools}))

    def test_duplicates_denied_with_no_partial_receipt(self):
        self._assert_denied(self._json({
            "version": 1,
            "tools": ["offline-check-001", "offline-check-001"],
        }))

    def test_duplicate_json_keys_denied_before_batch_review(self):
        self._assert_denied(self._run(
            b'{"version":1,"tools":["offline-check-001"],'
            b'"tools":["offline-check-002"]}'
        ))

    def test_nested_duplicate_json_keys_denied(self):
        self._assert_denied(self._run(
            b'{"version":1,"tools":["offline-check-001"],'
            b'"metadata":{"x":1,"x":2}}'
        ))

    def test_unknown_keys_and_metadata_are_rejected(self):
        for obj in (
            {"version": 1, "tools": ["offline-check-001"], "target": "example.com"},
            {"version": 1, "tools": ["offline-check-001"], "authorization": True},
            {"version": 1, "tools": ["offline-check-001"], "risk": 3},
            {"tools": ["offline-check-001"]},
            {},
        ):
            with self.subTest(keys=tuple(obj.keys())):
                self._assert_denied(self._json(obj))

    def test_non_exact_version_and_container_types_denied(self):
        for obj in (
            {"version": True, "tools": ["offline-check-001"]},
            {"version": 1.0, "tools": ["offline-check-001"]},
            {"version": "1", "tools": ["offline-check-001"]},
            {"version": 0, "tools": ["offline-check-001"]},
            {"version": 1, "tools": ("offline-check-001",)},
            {"version": 1, "tools": "offline-check-001"},
            {"version": 1, "tools": None},
            [1, "offline-check-001"],
        ):
            with self.subTest(obj=repr(obj)[:80]):
                if type(obj) is dict and type(obj.get("tools")) is tuple:
                    continue  # JSON tuples decode to lists; not a wire type.
                self._assert_denied(self._json(obj))

    def test_untrusted_noncanonical_ids_never_echoed(self):
        for value in (
            "offline-check-000", "offline-check-065",
            "offline-check-001\n", "offline-check-001/../../tmp",
            "http://example.com", "localhost", True, None, 1,
            "x" * 1024,
        ):
            with self.subTest(value=repr(value)[:32]):
                p = self._json({"version": 1, "tools": [value]})
                self._assert_denied(p)
                self.assertNotIn(b"example.com", p.stderr)

    def test_bounded_bytes_and_invalid_utf8_denied(self):
        for raw in (
            b"",
            b" " * 4097,
            b"\xff",
            b'{"version":1,"tools":["offline-check-001"]}\x00',
            b'{not-json}',
        ):
            self._assert_denied(self._run(raw))

    def test_nonfinite_json_constants_are_denied(self):
        for value in (b"NaN", b"Infinity", b"-Infinity"):
            raw = b'{"version":1,"tools":["offline-check-001"],"extra":' + value + b"}"
            self._assert_denied(self._run(raw))

    def test_overlong_seemingly_valid_input_still_denied(self):
        self._assert_denied(self._run(b" " * 4096 + b"{}"))

    def test_wrong_cli_flags_and_missing_arguments_do_not_echo_paths(self):
        p = subprocess.run(
            [sys.executable, "-m", "lightup.offline_executor_batch_cli_optin"],
            capture_output=True, check=False, timeout=15,
        )
        self._assert_denied(p)
        p = subprocess.run(
            [sys.executable, "-m", "lightup.offline_executor_batch_cli_optin",
             "--execute", "https://example.com"],
            capture_output=True, check=False, timeout=15,
        )
        self._assert_denied(p)

    def test_refuse_directory_or_missing_file_without_traceback(self):
        path = self.root / "missing.file"
        for location in (self.root, path):
            p = subprocess.run(
                [sys.executable, "-m", "lightup.offline_executor_batch_cli_optin",
                 "--input", str(location)],
                capture_output=True, check=False, timeout=15,
            )
            self._assert_denied(p)
            self.assertNotIn(str(location).encode(), p.stderr)

    def test_offline_engine_never_calls_executor_or_policy(self):
        # Real temp SQLite and genuine registry are used, but no dispatch,
        # policy decide or handler is ever permitted.
        from lightup.ai.orchestration import ToolExecutor
        from lightup.execution_policy import ExecutionPolicy
        from lightup.offline_executor_batch_cli_optin import _never_run
        with patch.object(ToolExecutor, "execute", side_effect=AssertionError("execute")):
            with patch.object(ExecutionPolicy, "decide", side_effect=AssertionError("decide")):
                result = _preview(("offline-check-001",))
        self.assertEqual(result["tools_reviewed"], 1)
        self.assertIs(result["permit_issued"], False)
        self.assertIs(result["execution_enabled"], False)
        self.assertIs(result["authorization_verified"], False)
        with self.assertRaisesRegex(AssertionError, "must never"):
            _never_run(None, {})


if __name__ == "__main__":
    unittest.main()
