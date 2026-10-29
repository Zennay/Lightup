"""In-process tests for #738 fictional-only no-zero-exit review CLI."""
import importlib.util
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_direct_grant_window_738_offline.py"
spec = importlib.util.spec_from_file_location("review_direct_grant_window_738_offline", SCRIPT)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)

VALID = (
    "--from-utc", "2026-10-14T11:00:00Z",
    "--until-utc", "2026-10-14T13:00:00Z",
    "--observed-at-utc", "2026-10-14T12:00:00Z",
)
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def invoke(args):
    stream = io.StringIO()
    with redirect_stdout(stream):
        code = cli.main(args)
    out = stream.getvalue()
    return code, json.loads(out), out


class OfflineDirectGrantWindowCliTests(unittest.TestCase):
    def assert_receipt(self, args, expected, reason):
        code, receipt, raw = invoke(args)
        self.assertEqual(receipt["decision"], expected)
        self.assertEqual(receipt["reason"], reason)
        self.assertEqual(code, 3 if expected == "REVIEW_ONLY" else 2)
        self.assertEqual(set(receipt), {"decision", "reason", *FLAGS})
        for name in FLAGS:
            self.assertIs(receipt[name], False)
        self.assertTrue(raw.endswith("\n"))
        self.assertEqual(len(raw.splitlines()), 1)
        self.assertNotIn("fixture", raw)
        self.assertNotIn("2026-10-14T", raw)

    def test_valid_utc_synthetic_data_never_exits_zero(self):
        self.assert_receipt(VALID, "REVIEW_ONLY", "temporal_shape_only")

    def test_date_arguments_can_be_reordered(self):
        args = VALID[4:] + VALID[2:4] + VALID[:2]
        self.assert_receipt(args, "REVIEW_ONLY", "temporal_shape_only")

    def test_exact_start_endpoint_is_inclusive(self):
        args = VALID[:4] + ("--observed-at-utc", VALID[1])
        self.assert_receipt(args, "REVIEW_ONLY", "temporal_shape_only")

    def test_exact_end_endpoint_is_inclusive(self):
        args = VALID[:4] + ("--observed-at-utc", VALID[3])
        self.assert_receipt(args, "REVIEW_ONLY", "temporal_shape_only")

    def test_out_of_window_holds(self):
        args = VALID[:4] + ("--observed-at-utc", "2026-10-14T14:00:00Z")
        self.assert_receipt(args, "HOLD", "outside_window")

    def test_invalid_equal_bounds_holds(self):
        args = VALID[:2] + ("--until-utc", VALID[1]) + VALID[4:]
        self.assert_receipt(args, "HOLD", "invalid_window")

    def test_reversed_bounds_holds(self):
        args = VALID[:2] + ("--until-utc", "2026-10-14T10:00:00Z") + VALID[4:]
        self.assert_receipt(args, "HOLD", "invalid_window")

    def test_missing_or_extra_arguments_hold(self):
        for args in ((), VALID[:-2], VALID + ("--unknown", "x"), VALID + ("x",),
                     ("--from-utc", "2026-10-14T11:00:00Z")):
            with self.subTest(args=args):
                self.assert_receipt(args, "HOLD", "invalid_input")

    def test_duplicate_or_unknown_flag_holds(self):
        args = ("--from-utc", VALID[1], "--from-utc", VALID[3]) + VALID[4:]
        self.assert_receipt(args, "HOLD", "invalid_input")
        args = ("--from-utc", VALID[1], "--other", VALID[3]) + VALID[4:]
        self.assert_receipt(args, "HOLD", "invalid_input")

    def test_non_string_fields_fail_closed_without_error_detail(self):
        for value in (None, False, 0, 5, {}, [], b"2026-10-14T11:00:00Z"):
            with self.subTest(value=str(value)):
                args = list(VALID)
                args[1] = value
                self.assert_receipt(args, "HOLD", "invalid_input")

    def test_strict_ascii_timestamp_canonicalization(self):
        bad = (
            "2026-1-14T11:00:00Z", "2026-10-14T1:00:00Z",
            "2026-10-14 11:00:00Z", "2026-10-14T11:00:00+00:00",
            "2026-10-14T11:00:00.0Z", "2026-10-14T11:00:00z",
            "2026-10-14T11:00:00Z\n", "2026-10-14T11:00:00ℤ",
            "2026-10-14T11:00:60Z", "2026-02-30T11:00:00Z",
            "2026-13-14T11:00:00Z", "0000-10-14T11:00:00Z",
            "2026-10-14T25:00:00Z", "2026-10-14T11:61:00Z",
            "99999-10-14T11:00:00Z",
        )
        for value in bad:
            with self.subTest(value=value):
                args = list(VALID)
                args[1] = value
                self.assert_receipt(args, "HOLD", "invalid_input")

    def test_boolean_and_number_values_cannot_be_promoted(self):
        self.assert_receipt([VALID[0], True, *VALID[2:]], "HOLD", "invalid_input")
        self.assert_receipt([VALID[0], 123, *VALID[2:]], "HOLD", "invalid_input")

    def test_read_only_networkless_database_less_with_synthetic_only_data(self):
        with patch("socket.create_connection", side_effect=AssertionError("network")), \
             patch("socket.socket", side_effect=AssertionError("network")), \
             patch("sqlite3.connect", side_effect=AssertionError("database")):
            self.assert_receipt(VALID, "REVIEW_ONLY", "temporal_shape_only")

    def test_does_not_echo_private_input(self):
        malicious = "SENSITIVE_GRANT_ID_FOR_TEST_ONLY"
        args = (VALID[0], malicious) + VALID[2:]
        _, _, raw = invoke(args)
        self.assertNotIn(malicious, raw)
        self.assertNotIn("Traceback", raw)

    def test_never_returns_exit_code_zero(self):
        for args in (VALID, (), VALID[:-2]):
            code, _, _ = invoke(args)
            self.assertIn(code, (2, 3))

    def test_direct_receipt_method_survives_exception(self):
        with patch.object(cli, "_evaluate", side_effect=RuntimeError("private-data-test")):
            self.assert_receipt(VALID, "HOLD", "invalid_input")


if __name__ == "__main__":
    unittest.main()
