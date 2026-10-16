"""Local test-only risk-decision audit integrity, no live approvals."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import unittest
from contextlib import closing
from pathlib import Path

from scope_897_offline_risk_record_guard import review_json, review_record, main

_SCRIPT = Path(__file__).with_name("scope_897_offline_risk_record_guard.py")
_APPROVAL = "aabbccdd-eeff-4abc-8def-aabbccddeeff"
_SAMPLE = {
    "approval_id": _APPROVAL,
    "requested_by": "client-demo",
    "reviewer_id": "operator-reviewer",
    "status": "pending",
    "decided_by": None,
    "decided_at": None,
}
_FLAGS = ("grants_authority", "permits_execution", "dispatch_allowed", "scans_allowed", "deploy_allowed", "release_allowed")


class _IdentityAdapter:
    def __init__(self, value: str) -> None:
        self.value = value
        self.calls = 0

    def __conform__(self, protocol: object) -> object:
        self.calls += 1
        return self.value if protocol is sqlite3.PrepareProtocol else None

    def __eq__(self, other: object) -> bool:
        self.calls += 1
        return other == self.value


class _StringSubclass(str):
    def __eq__(self, other: object) -> bool:
        return False


class RiskRecordGuardTests(unittest.TestCase):
    def assertNoAuthority(self, receipt: dict[str, object]) -> None:
        self.assertIn(receipt["decision"], ("HOLD", "REVIEW_ONLY"))
        self.assertEqual(set(receipt), {"decision", *_FLAGS})
        for flag in _FLAGS:
            self.assertIs(receipt[flag], False)

    def test_fictional_pending_record_is_review_only_not_decision(self) -> None:
        receipt = review_record(_SAMPLE)
        self.assertEqual(receipt["decision"], "REVIEW_ONLY")
        self.assertNoAuthority(receipt)

    def test_caller_record_is_not_mutated(self) -> None:
        source = dict(_SAMPLE)
        review_record(source)
        self.assertEqual(source, _SAMPLE)

    def test_sqlite_identity_adapter_never_runs_during_preflight(self) -> None:
        forged = _IdentityAdapter(_APPROVAL)
        receipt = review_record({**_SAMPLE, "approval_id": forged})
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertEqual(forged.calls, 0)
        self.assertNoAuthority(receipt)

    def test_identity_type_confusions_are_held(self) -> None:
        samples = (
            ("approval_id", _StringSubclass(_APPROVAL)),
            ("approval_id", b"approval"),
            ("approval_id", True),
            ("requested_by", _StringSubclass("client-demo")),
            ("requested_by", b"client-demo"),
            ("reviewer_id", 1),
            ("status", _StringSubclass("pending")),
        )
        for field, value in samples:
            with self.subTest(field=field, kind=type(value).__name__):
                receipt = review_record({**_SAMPLE, field: value})
                self.assertEqual(receipt["decision"], "HOLD")
                self.assertNoAuthority(receipt)

    def test_self_approval_is_never_a_positive_preview(self) -> None:
        receipt = review_record({**_SAMPLE, "reviewer_id": "client-demo"})
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertNoAuthority(receipt)

    def test_stale_pending_decision_audit_is_held(self) -> None:
        for field, value in (("decided_by", "operator-old"), ("decided_at", "2026-10-12T01:00:00Z")):
            with self.subTest(field=field):
                receipt = review_record({**_SAMPLE, field: value})
                self.assertEqual(receipt["decision"], "HOLD")
                self.assertNoAuthority(receipt)

    def test_malformed_shape_and_values_hold(self) -> None:
        cases = (
            None, [], "pending", {"status": "pending"},
            {**_SAMPLE, "requested_by": ""},
            {**_SAMPLE, "requested_by": "  "},
            {**_SAMPLE, "requested_by": "client\u202edemo"},
            {**_SAMPLE, "requested_by": "operator-reviewer"},
            {**_SAMPLE, "status": "approved"},
            {**_SAMPLE, "status": None},
            {**_SAMPLE, "extra": "do-not-grant"},
            {**_SAMPLE, "approval_id": _APPROVAL.upper()},
            {**_SAMPLE, "decided_by": b"corrupted"},
        )
        for obj in cases:
            with self.subTest(kind=type(obj).__name__):
                receipt = review_record(obj)
                self.assertEqual(receipt["decision"], "HOLD")
                self.assertNoAuthority(receipt)

    def test_in_memory_sqlite_corrupt_requester_blob_is_read_only_hold(self) -> None:
        with closing(sqlite3.connect(":memory:")) as con:
            con.execute("CREATE TABLE risk_approvals (approval_id TEXT, requested_by TEXT, status TEXT, decided_by TEXT, decided_at TEXT)")
            con.execute("INSERT INTO risk_approvals VALUES (?,?,?,?,?)", (
                _APPROVAL, sqlite3.Binary(b"operator-reviewer"), "pending", None, None,
            ))
            con.row_factory = sqlite3.Row
            before = con.execute("SELECT * FROM risk_approvals").fetchone()
            receipt = review_record({**dict(before), "reviewer_id": "operator-reviewer"})
            after = con.execute("SELECT * FROM risk_approvals").fetchone()
            self.assertEqual(receipt["decision"], "HOLD")
            self.assertEqual(tuple(before), tuple(after))
            self.assertIs(type(after["requested_by"]), bytes)
            self.assertNoAuthority(receipt)

    def test_in_memory_sqlite_stale_audit_is_read_only_hold(self) -> None:
        with closing(sqlite3.connect(":memory:")) as con:
            con.execute("CREATE TABLE risk_approvals (approval_id TEXT, requested_by TEXT, status TEXT, decided_by TEXT, decided_at TEXT)")
            con.execute("INSERT INTO risk_approvals VALUES (?,?,?,?,?)", (_APPROVAL, "client-demo", "pending", "operator-old", "2026-10-12T01:00:00Z"))
            con.row_factory = sqlite3.Row
            original = con.execute("SELECT * FROM risk_approvals").fetchone()
            receipt = review_record({**dict(original), "reviewer_id": "operator-reviewer"})
            saved = con.execute("SELECT * FROM risk_approvals").fetchone()
            self.assertEqual(receipt["decision"], "HOLD")
            self.assertEqual(tuple(saved), tuple(original))
            self.assertNoAuthority(receipt)

    def test_duplicate_keys_bad_bytes_and_oversize_hold(self) -> None:
        raw = (
            b'{"approval_id":"x","approval_id":"y"}',
            b'{"approval_id":"x","unknown":1}',
            b'NaN', b'\xff', b'{', b'[]', b' ' * 3073,
        )
        for item in raw:
            with self.subTest(raw=item[:30]):
                receipt = review_json(item)
                self.assertEqual(receipt["decision"], "HOLD")
                self.assertNoAuthority(receipt)

    def test_cli_requires_explicit_flag_and_never_dumps_input(self) -> None:
        for args, expected_code in (([], 2), (["--offline-synthetic-only"], 3)):
            proc = subprocess.run([sys.executable, str(_SCRIPT), *args], input=json.dumps(_SAMPLE).encode(), capture_output=True, timeout=5)
            self.assertEqual(proc.returncode, expected_code)
            self.assertFalse(proc.stderr)
            self.assertNoAuthority(json.loads(proc.stdout))
            self.assertNotIn(_APPROVAL.encode(), proc.stdout + proc.stderr)

    def test_cli_rejects_corrupt_row_without_echo(self) -> None:
        secret = "SECRET-CUSTOMER-CLAIM"
        proc = subprocess.run([sys.executable, str(_SCRIPT), "--offline-synthetic-only"], input=json.dumps({**_SAMPLE, "requested_by": secret}).encode(), capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 2)
        self.assertNoAuthority(json.loads(proc.stdout))
        self.assertFalse(proc.stderr)
        self.assertNotIn(secret.encode(), proc.stdout + proc.stderr)



    def test_polymorphic_dictionary_keys_are_rejected_before_caller_methods(self) -> None:
        class _TrackedKey(str):
            def __new__(cls, value):
                obj = str.__new__(cls, value)
                obj.calls = 0
                return obj

            def __hash__(self):
                self.calls += 1
                return str.__hash__(self)

            def __eq__(self, other):
                self.calls += 1
                return str.__eq__(self, other)

        trap = _TrackedKey("approval_id")
        payload = dict(_SAMPLE)
        original_value = payload.pop("approval_id")
        payload[trap] = original_value
        trap.calls = 0
        receipt = review_record(payload)
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertEqual(trap.calls, 0, "untrusted key methods must not run")
        self.assertNoAuthority(receipt)
        self.assertEqual(len(payload), len(_SAMPLE))

    def test_nonstring_dictionary_keys_fail_before_equality_or_hashing(self) -> None:
        class _SpoofKey:
            def __init__(self):
                self.calls = 0

            def __hash__(self):
                self.calls += 1
                return hash("approval_id")

            def __eq__(self, other):
                self.calls += 1
                return other == "approval_id"

        trap = _SpoofKey()
        payload = dict(_SAMPLE)
        value = payload.pop("approval_id")
        payload[trap] = value
        trap.calls = 0
        receipt = review_record(payload)
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertEqual(trap.calls, 0, "untrusted key methods must not run")
        self.assertNoAuthority(receipt)


    def test_programmatic_cli_rejects_equality_spoofed_argv_without_stdin_read(self) -> None:
        import io
        from contextlib import redirect_stdout
        from unittest.mock import patch

        class _NoStdin:
            @property
            def buffer(self):
                raise AssertionError("untrusted argv must never trigger a stdin read")

        class _ForgedArgs:
            def __init__(self):
                self.calls = 0

            def __eq__(self, other):
                self.calls += 1
                return True

            @property
            def __class__(self):
                return list

        forged = _ForgedArgs()
        output = io.StringIO()
        with patch.object(sys, "stdin", _NoStdin()), redirect_stdout(output):
            rc = main(forged)  # type: ignore[arg-type]
        self.assertEqual(rc, 2)
        self.assertEqual(forged.calls, 0)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertNoAuthority(receipt)

    def test_programmatic_cli_rejects_str_subclass_optin_without_comparison(self) -> None:
        import io
        from contextlib import redirect_stdout
        from unittest.mock import patch

        class _NoStdin:
            @property
            def buffer(self):
                raise AssertionError("subclass argv must never trigger stdin")

        class _SpoofArg(str):
            def __new__(cls, value):
                obj = str.__new__(cls, value)
                obj.calls = 0
                return obj

            def __eq__(self, other):
                self.calls += 1
                return True

        forged = _SpoofArg("--offline-synthetic-only")
        output = io.StringIO()
        with patch.object(sys, "stdin", _NoStdin()), redirect_stdout(output):
            rc = main([forged])
        self.assertEqual(rc, 2)
        self.assertEqual(forged.calls, 0)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertNoAuthority(receipt)

if __name__ == "__main__":
    unittest.main()
