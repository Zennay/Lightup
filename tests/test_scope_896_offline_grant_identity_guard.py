"""No-authority exact grant ID preview: local only, independent of LightUp."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path
from uuid import uuid4

from scope_896_offline_grant_identity_guard import review_identity, review_json, main

_SCRIPT = Path(__file__).with_name("scope_896_offline_grant_identity_guard.py")
_SAMPLE = "aabbccdd-eeff-4abc-8def-aabbccddeeff"
_FLAGS = (
    "grants_authority", "permits_execution", "dispatch_allowed",
    "scans_allowed", "deploy_allowed", "release_allowed",
)


class _SqliteAdapter:
    def __init__(self, value: str) -> None:
        self.value = value
        self.calls = 0

    def __conform__(self, protocol: object) -> str | None:
        self.calls += 1
        return self.value if protocol is sqlite3.PrepareProtocol else None

    def __eq__(self, other: object) -> bool:
        self.calls += 1
        return other == self.value

    def __str__(self) -> str:
        self.calls += 1
        return self.value


class _GrantSubclass(str):
    def __eq__(self, other: object) -> bool:
        return True


class _ClassForgery:
    @property
    def __class__(self):
        return str


class GrantIdentityReviewTests(unittest.TestCase):
    def assertNoAuthority(self, result: dict[str, object]) -> None:
        self.assertIn(result["decision"], ("HOLD", "REVIEW_ONLY"))
        self.assertEqual(set(result), {"decision", *_FLAGS})
        for flag in _FLAGS:
            self.assertIs(result[flag], False)

    def test_fictional_exact_uuid4_is_review_only_not_permission(self) -> None:
        for value in (_SAMPLE, str(uuid4())):
            with self.subTest(value=value):
                receipt = review_identity(value)
                self.assertEqual(receipt["decision"], "REVIEW_ONLY")
                self.assertNoAuthority(receipt)

    def test_adaptable_equality_spoofer_never_invokes_caller_methods(self) -> None:
        forged = _SqliteAdapter(_SAMPLE)
        receipt = review_identity(forged)
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertEqual(forged.calls, 0)
        self.assertNoAuthority(receipt)

    def test_string_subclasses_and_class_spoofs_fail(self) -> None:
        for candidate in (_GrantSubclass(_SAMPLE), _ClassForgery()):
            with self.subTest(kind=type(candidate).__name__):
                receipt = review_identity(candidate)
                self.assertEqual(receipt["decision"], "HOLD")
                self.assertNoAuthority(receipt)

    def test_noncanonical_id_shapes_hold(self) -> None:
        variants = (
            None, False, True, 0, 1, [], {}, b"", "", " ",
            _SAMPLE.upper(), _SAMPLE.replace("-", ""), _SAMPLE + " ",
            _SAMPLE.replace("4abc", "1abc"), _SAMPLE.replace("8def", "7def"),
            _SAMPLE.replace("a", "O", 1), "\u202e" + _SAMPLE,
        )
        for value in variants:
            with self.subTest(kind=type(value).__name__):
                receipt = review_identity(value)
                self.assertEqual(receipt["decision"], "HOLD")
                self.assertNoAuthority(receipt)

    def test_strict_json_rejects_duplicates_extensions_and_nonjson(self) -> None:
        raw_items = (
            b'{}', b'[]', b'{', b'null', b'NaN', b'\xff', b' ' * 1025,
            b'{"grant_id":"' + _SAMPLE.encode() + b'","grant_id":"' + _SAMPLE.encode() + b'"}',
            b'{"grant_id":"' + _SAMPLE.encode() + b'","client_id":"fake"}',
            b'{"grant_id":123}',
        )
        for raw in raw_items:
            with self.subTest(raw=raw[:40]):
                receipt = review_json(raw)
                self.assertEqual(receipt["decision"], "HOLD")
                self.assertNoAuthority(receipt)

    def test_exact_boundary_is_bounded_and_non_authorizing(self) -> None:
        body = json.dumps({"grant_id": _SAMPLE}).encode()
        padded = body + b' ' * (1024 - len(body))
        self.assertEqual(review_json(padded)["decision"], "REVIEW_ONLY")
        result = review_json(padded + b' ')
        self.assertEqual(result["decision"], "HOLD")
        self.assertNoAuthority(result)

    def test_cli_without_opt_in_is_unconditionally_hold(self) -> None:
        proc = subprocess.run([sys.executable, str(_SCRIPT)], input=json.dumps({"grant_id": _SAMPLE}).encode(), capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)["decision"], "HOLD")
        self.assertFalse(proc.stderr)

    def test_cli_correct_fictional_shape_is_still_exit3_review_only(self) -> None:
        proc = subprocess.run([sys.executable, str(_SCRIPT), "--offline-synthetic-only"], input=json.dumps({"grant_id": _SAMPLE}).encode(), capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 3)
        self.assertNoAuthority(json.loads(proc.stdout))
        self.assertFalse(proc.stderr)

    def test_cli_noncanonical_exits2_without_input_echo(self) -> None:
        secret = "SECRET-CLIENT-REFERENCE"
        proc = subprocess.run([sys.executable, str(_SCRIPT), "--offline-synthetic-only"], input=json.dumps({"grant_id": secret}).encode(), capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 2)
        self.assertNoAuthority(json.loads(proc.stdout))
        self.assertNotIn(secret.encode(), proc.stdout + proc.stderr)
        self.assertFalse(proc.stderr)

    def test_cli_no_grant_side_effect_flags_even_for_fictional_match(self) -> None:
        receipt = review_json(json.dumps({"grant_id": _SAMPLE}).encode())
        self.assertEqual(receipt["decision"], "REVIEW_ONLY")
        self.assertNoAuthority(receipt)



    def test_direct_cli_rejects_spoofed_argument_container_before_stdin(self) -> None:
        import io
        from contextlib import redirect_stdout
        from unittest.mock import patch

        class _GuardedInput:
            @property
            def buffer(self):
                raise AssertionError("must not read stdin on forged argv")

        class _ForgedArgv:
            def __init__(self):
                self.comparisons = 0

            def __eq__(self, other):
                self.comparisons += 1
                return True

            @property
            def __class__(self):
                return list

        forged = _ForgedArgv()
        out = io.StringIO()
        with patch.object(sys, "stdin", _GuardedInput()), redirect_stdout(out):
            result = main(forged)  # type: ignore[arg-type]
        self.assertEqual(result, 2)
        self.assertEqual(forged.comparisons, 0)
        receipt = json.loads(out.getvalue())
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertNoAuthority(receipt)

    def test_direct_cli_rejects_equality_spoofed_string_option(self) -> None:
        import io
        from contextlib import redirect_stdout
        from unittest.mock import patch

        class _GuardedInput:
            @property
            def buffer(self):
                raise AssertionError("must not read stdin on forged option")

        class _StringOption(str):
            def __new__(cls, text):
                item = str.__new__(cls, text)
                item.comparisons = 0
                return item

            def __eq__(self, other):
                self.comparisons += 1
                return True

        token = _StringOption("--offline-synthetic-only")
        out = io.StringIO()
        with patch.object(sys, "stdin", _GuardedInput()), redirect_stdout(out):
            result = main([token])
        self.assertEqual(result, 2)
        self.assertEqual(token.comparisons, 0)
        receipt = json.loads(out.getvalue())
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertNoAuthority(receipt)

if __name__ == "__main__":
    unittest.main()
