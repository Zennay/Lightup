"""Real subprocess end-to-end acceptance for opt-in fictional stdin only (#1495)."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
CMD = [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495", "--synthetic-only"]
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}


def fixture() -> dict[str, object]:
    return {
        "review_at": "2026-10-16T12:00:00Z",
        "proposals": [{
            "asset": "desk.example.test",
            "capability": "inventory_read",
            "risk": 2,
            "valid_from": "2026-10-16T11:00:00Z",
            "valid_until": "2026-10-16T13:00:00Z",
        }],
    }


def invoke(value: bytes, *, cmd: list[str] = CMD):
    return subprocess.run(
        cmd, cwd=ROOT, env=ENV, input=value, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=12, check=False,
    )


class SyntheticNoticeStdinCli1495(unittest.TestCase):
    def assert_hold(self, run) -> None:
        self.assertEqual(run.returncode, 3, run.stderr)
        self.assertIn(b"HOLD", run.stdout)
        self.assertIn(b"NOT AUTHORIZED", run.stdout)
        self.assertNotIn(b"desk.example.test", run.stdout)
        self.assertFalse(run.stderr)

    def test_real_stdin_human_notice_has_no_success_exit(self):
        run = invoke(json.dumps(fixture()).encode())
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertIn(b"REVIEW ONLY", run.stdout)
        self.assertIn(b"NOT AUTHORIZED", run.stdout)
        self.assertIn(b"desk.example.test", run.stdout)
        self.assertIn(b"inventory_read", run.stdout)
        self.assertFalse(run.stderr)

    def test_high_risk_stepup_keeps_exit_two_not_zero(self):
        data = fixture()
        data["proposals"][0]["risk"] = 5
        run = invoke(json.dumps(data).encode())
        self.assertEqual(run.returncode, 2)
        self.assertIn(b"independent step-up", run.stdout)
        self.assertIn(b"NOT AUTHORIZED", run.stdout)

    def test_array_two_distinct_assets_sorted_deterministically(self):
        data = fixture()
        second = data["proposals"][0].copy()
        second["asset"] = "alpha.example.test"
        data["proposals"].append(second)
        direct = invoke(json.dumps(data).encode())
        reverse = data.copy()
        reverse["proposals"] = list(reversed(data["proposals"]))
        swapped = invoke(json.dumps(reverse).encode())
        self.assertEqual(direct.returncode, 2)
        self.assertEqual(swapped.returncode, 2)
        self.assertEqual(direct.stdout, swapped.stdout)
        self.assertLess(direct.stdout.index(b"alpha.example.test"), direct.stdout.index(b"desk.example.test"))

    def test_duplicate_json_outer_key_is_hold(self):
        raw = json.dumps(fixture())
        raw = raw.replace('"review_at":', '"review_at": "2026-10-16T11:00:00Z", "review_at":', 1)
        self.assert_hold(invoke(raw.encode()))

    def test_duplicate_entry_key_is_hold_even_equal(self):
        raw = json.dumps(fixture()).replace('"asset":', '"asset": "desk.example.test", "asset":', 1)
        self.assert_hold(invoke(raw.encode()))

    def test_bad_shape_unexpected_fields_and_wrong_records(self):
        cases = [
            b"{}", b"[]", b"null", b'"string"', b"true", b"NaN", b"{",
            json.dumps({"review_at": fixture()["review_at"], "proposals": []}).encode(),
            json.dumps({**fixture(), "extra": True}).encode(),
            json.dumps({**fixture(), "proposals": [None]}).encode(),
            json.dumps({**fixture(), "proposals": [dict(fixture()["proposals"][0], other=1)]}).encode(),
            json.dumps({**fixture(), "proposals": list(fixture()["proposals"]) * 33}).encode(),
        ]
        for raw in cases:
            with self.subTest(raw=raw[:70]):
                self.assert_hold(invoke(raw))

    def test_rejects_real_assets_and_echo_sensitive_identity_never(self):
        data = fixture()
        data["proposals"][0]["asset"] = "customer-account-real.example.com"
        self.assert_hold(invoke(json.dumps(data).encode()))

    def test_rejects_noncanonical_timestamp_formats(self):
        for timestamp in ("2026-10-16T12:00:00+00:00", "2026-10-16T12:00:00.000Z",
                          "2026-10-16t12:00:00Z", "2026-10-16T12:00:00z",
                          "2026-2-16T12:00:00Z", "2026-10-16T12:00:60Z",
                          "2026-10-16", 3, None):
            with self.subTest(timestamp=timestamp):
                data = fixture()
                data["review_at"] = timestamp
                self.assert_hold(invoke(json.dumps(data).encode()))

    def test_entry_timestamp_parser_is_exact_z_only(self):
        data = fixture()
        data["proposals"][0]["valid_until"] = "2026-10-16T13:00:00+00:00"
        self.assert_hold(invoke(json.dumps(data).encode()))

    def test_rejects_bool_string_float_and_nonfinite_risk(self):
        for risk in (False, 3.5, "3", 1e309):
            with self.subTest(risk=risk):
                data = fixture()
                data["proposals"][0]["risk"] = risk
                self.assert_hold(invoke(json.dumps(data).encode()))

    def test_rejects_invalid_utf8_and_lone_surrogate_json(self):
        self.assert_hold(invoke(b"\xff\xfe"))
        self.assert_hold(invoke(b'{"review_at": "\\ud800", "proposals": []}'))

    def test_65537_bytes_aborts_before_parser(self):
        self.assert_hold(invoke(b"X" * 65537))

    def test_blank_inputs_and_no_opt_in_hold(self):
        self.assert_hold(invoke(b""))
        self.assert_hold(invoke(json.dumps(fixture()).encode(), cmd=CMD[:-1]))
        self.assert_hold(invoke(json.dumps(fixture()).encode(), cmd=CMD+["--scan"]))

    def test_expired_scope_cannot_be_reported_as_review_only(self):
        data = fixture()
        data["proposals"][0]["valid_until"] = "2026-10-16T11:59:59Z"
        self.assert_hold(invoke(json.dumps(data).encode()))


if __name__ == "__main__":
    unittest.main()
