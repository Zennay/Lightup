"""No-permit, no-network, nonzero-exit fixture CLI acceptance (#647)."""
import importlib.util
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_fictional_grant_storage_647_offline.py"
spec = importlib.util.spec_from_file_location(
    "audit_fictional_grant_storage_647_offline", SCRIPT
)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)

START = "2026-10-14T12:00:00+00:00"
UNTIL = "2026-10-14T12:15:00+00:00"
VALID = (
    "--expected-start-utc", START,
    "--expected-until-utc", UNTIL,
    "--stored-start-utc", START,
    "--stored-until-utc", UNTIL,
)
FLAGS = (
    "authorization_verified", "grant_issued", "execution_enabled",
    "release_approved",
)


def invoke(args):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli.main(args)
    raw = buffer.getvalue()
    return code, json.loads(raw), raw


class SyntheticGrantStorageAuditCliTests(unittest.TestCase):
    def assert_result(self, args, decision, reason):
        status, receipt, raw = invoke(args)
        self.assertEqual(status, 3 if decision == "REVIEW_ONLY" else 2)
        self.assertEqual((receipt["decision"], receipt["reason"]),
                         (decision, reason))
        self.assertEqual(set(receipt), {"decision", "reason", *FLAGS})
        for name in FLAGS:
            self.assertIs(receipt[name], False)
        self.assertTrue(raw.endswith("\n"))
        self.assertEqual(len(raw.splitlines()), 1)
        self.assertNotIn("2026-10", raw)
        self.assertNotIn("fixture.example", raw)

    def test_exact_canonical_utc_matches_only_review(self):
        self.assert_result(VALID, "REVIEW_ONLY", "shape_and_values_match")

    def test_reordered_arguments_match(self):
        args = VALID[4:6] + VALID[:4] + VALID[6:]
        self.assert_result(args, "REVIEW_ONLY", "shape_and_values_match")

    def test_widened_persisted_expiry_holds(self):
        args = VALID[:-1] + ("2027-10-14T12:15:00+00:00",)
        self.assert_result(args, "HOLD", "expiry_mismatch")

    def test_backdated_persisted_start_holds(self):
        args = VALID[:5] + ("2025-10-14T12:00:00+00:00",) + VALID[6:]
        self.assert_result(args, "HOLD", "start_mismatch")

    def test_earlier_persisted_expiry_holds(self):
        args = VALID[:-1] + ("2026-10-14T12:14:00+00:00",)
        self.assert_result(args, "HOLD", "expiry_mismatch")

    def test_invalid_expected_window_holds(self):
        args = VALID[:3] + (START,) + VALID[4:]
        self.assert_result(args, "HOLD", "expected_window")

    def test_explicit_none_input_is_refused(self):
        args = list(VALID)
        args[-1] = None
        self.assert_result(args, "HOLD", "invalid_input")

    def test_wrong_stored_type_refused(self):
        args = list(VALID)
        args[5] = False
        self.assert_result(args, "HOLD", "invalid_input")

    def test_missing_or_extra_flags_refused(self):
        for value in ((), VALID[:-2], VALID + ("--extra", "SENSITIVE")):
            with self.subTest(value=repr(value)):
                self.assert_result(value, "HOLD", "invalid_input")

    def test_repeated_expected_key_refused(self):
        args = list(VALID)
        args[4] = args[0]
        self.assert_result(args, "HOLD", "invalid_input")

    def test_unknown_key_refused(self):
        args = list(VALID)
        args[6] = "--something-else"
        self.assert_result(args, "HOLD", "invalid_input")

    def test_bad_expected_start_refused(self):
        args = list(VALID)
        args[1] = "2026-10-14T12:00:00Z"
        self.assert_result(args, "HOLD", "expected_start")

    def test_bad_expected_expiry_refused(self):
        args = list(VALID)
        args[3] = "2026-10-14T12:15:00+01:00"
        self.assert_result(args, "HOLD", "expected_expiry")

    def test_bad_stored_start_refused(self):
        args = list(VALID)
        args[5] = "2026-10-14T12:00:00Z"
        self.assert_result(args, "HOLD", "stored_start")

    def test_bad_stored_expiry_refused(self):
        args = list(VALID)
        args[-1] = "2026-10-14T12:15:00.000000+00:00"
        self.assert_result(args, "HOLD", "stored_expiry")

    def test_input_values_are_never_echoed(self):
        secret = "MY_PRIVATE_FAKE_TOKEN"
        args = list(VALID)
        args[1] = secret
        code, _, raw = invoke(args)
        self.assertEqual(code, 2)
        self.assertNotIn(secret, raw)
        self.assertNotIn("Traceback", raw)

    def test_no_exit_zero_even_when_window_matches(self):
        for value in (VALID, (), VALID[:-2]):
            code, _, _ = invoke(value)
            self.assertIn(code, (2, 3))
            self.assertNotEqual(code, 0)

    def test_no_socket_or_db_for_audit(self):
        with patch("socket.socket", side_effect=AssertionError("network")), \
             patch("socket.create_connection", side_effect=AssertionError("network")), \
             patch("sqlite3.connect", side_effect=AssertionError("db")):
            self.assert_result(VALID, "REVIEW_ONLY", "shape_and_values_match")

    def test_exception_is_sanitized_and_denied(self):
        with patch.object(cli, "review_fixture_arguments",
                          side_effect=RuntimeError("PRIVATE_SENSITIVE")):
            code, receipt, raw = invoke(VALID)
            self.assertEqual(code, 2)
            self.assertEqual(receipt["reason"], "invalid_input")
            self.assertNotIn("PRIVATE_SENSITIVE", raw)

    def test_microsecond_precision_compares_exact(self):
        a = "2026-10-14T12:00:00.123456+00:00"
        b = "2026-10-14T12:15:00.123456+00:00"
        args = (VALID[0], a, VALID[2], b, VALID[4], a, VALID[6], b)
        self.assert_result(args, "REVIEW_ONLY", "shape_and_values_match")


if __name__ == "__main__":
    unittest.main()
