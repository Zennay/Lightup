"""Offline, genuine subprocess regressions for untrusted expiry cohort review."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import review_scope_expiry_cohort_20261015_offline as reviewer


def document():
    return {
        "as_of_utc": "2026-10-15T12:00:00Z",
        "horizon_hours": 24,
        "windows": [
            {"valid_from": "2026-10-13T00:00:00Z",
             "valid_until": "2026-10-14T00:00:00Z"},
            {"valid_from": "2026-10-16T13:00:00Z",
             "valid_until": "2026-10-17T13:00:00Z"},
            {"valid_from": "2026-10-14T00:00:00Z",
             "valid_until": "2026-10-16T12:00:00Z"},
            {"valid_from": "2026-10-14T00:00:00Z",
             "valid_until": "2026-10-18T12:00:00Z"},
        ],
    }


def encoded(data):
    return json.dumps(data, separators=(",", ":")).encode("utf-8")


def subprocess_review(raw: bytes, *args: str):
    process = subprocess.run(
        [sys.executable, str(ROOT / "scripts" /
                             "review_scope_expiry_cohort_20261015_offline.py"), *args],
        input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=5, check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    lines = process.stdout.decode("ascii").splitlines()
    assert len(lines) == 1, (process.returncode, lines, process.stderr)
    return process.returncode, json.loads(lines[0]), process.stderr


class ExpiryCohortOfflineTests(unittest.TestCase):
    def assertNoAuthority(self, receipt):
        self.assertEqual(
            {key: receipt[key] for key in reviewer.DENIAL_FLAGS},
            reviewer.DENIAL_FLAGS,
        )
        for field in reviewer.DENIAL_FLAGS:
            self.assertIs(receipt[field], False)

    def test_four_disjoint_cohorts(self):
        data = encoded(document())
        result = reviewer.review(data)
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(
            [result[k] for k in (
                "expired", "not_yet_started",
                "current_expiring_within_horizon", "current_later"
            )], [1, 1, 1, 1],
        )
        self.assertNoAuthority(result)

    def test_valid_end_is_inclusive_and_after_end_expired(self):
        claim = {
            "valid_from": "2026-10-15T11:00:00Z",
            "valid_until": "2026-10-15T12:00:00Z",
        }
        packet = document()
        packet["windows"] = [claim]
        result = reviewer.review(encoded(packet))
        self.assertEqual(result["current_expiring_within_horizon"], 1)
        packet["as_of_utc"] = "2026-10-15T12:00:01Z"
        self.assertEqual(reviewer.review(encoded(packet))["expired"], 1)

    def test_valid_start_inclusive(self):
        packet = document()
        packet["windows"] = [{
            "valid_from": "2026-10-15T12:00:00Z",
            "valid_until": "2026-10-15T14:00:00Z",
        }]
        self.assertEqual(
            reviewer.review(encoded(packet))["current_expiring_within_horizon"], 1,
        )

    def test_horizon_inclusive_edge_and_beyond(self):
        packet = document()
        packet["horizon_hours"] = 1
        packet["windows"] = [{
            "valid_from": "2026-10-15T11:00:00Z",
            "valid_until": "2026-10-15T13:00:00Z",
        }]
        self.assertEqual(reviewer.review(encoded(packet))["current_expiring_within_horizon"], 1)
        packet["windows"][0]["valid_until"] = "2026-10-15T13:00:01Z"
        self.assertEqual(reviewer.review(encoded(packet))["current_later"], 1)

    def test_reject_inverted_and_zero_duration_atomic(self):
        packet = document()
        for end in ("2026-10-15T10:00:00Z", "2026-10-15T11:00:00Z"):
            with self.subTest(end=end):
                packet["windows"][0] = {
                    "valid_from": "2026-10-15T11:00:00Z", "valid_until": end,
                }
                with self.assertRaises(ValueError):
                    reviewer.review(encoded(packet))

    def test_invalid_horizon_types_and_bounds(self):
        for value in (True, False, None, 0, 721, -1, 1.0, "24", [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                packet = document()
                packet["horizon_hours"] = value
                reviewer.review(encoded(packet))

    def test_reject_noncanonical_json_int_tokens(self):
        packet = encoded(document())
        for token in (b"-0", b"1e0", b"1.0", b"99999", b"-1"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                reviewer.review(packet.replace(b'"horizon_hours":24', b'"horizon_hours":' + token))

    def test_reject_duplicate_json_keys_even_deeply_nested(self):
        packet = encoded(document())
        tampered = packet.replace(
            b'"valid_until":"2026-10-14T00:00:00Z"',
            b'"valid_until":"2026-10-14T00:00:00Z",'
            b'"valid_until":"2026-10-18T00:00:00Z"',
        )
        with self.assertRaises(ValueError):
            reviewer.review(tampered)
        with self.assertRaises(ValueError):
            reviewer.review(packet.replace(b'"horizon_hours":24',
                                           b'"horizon_hours":24,"horizon_hours":24'))

    def test_reject_unknown_fields_targets_and_client_ids(self):
        packet = document()
        for field in ("client_id", "target", "approved", "grant_id", "asset"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                packet["windows"][0][field] = "sensitive-customer.example"
                reviewer.review(encoded(packet))
                del packet["windows"][0][field]

    def test_reject_unicode_digit_and_24_hour_rollover(self):
        packet = document()
        for value in (
            "２０２６-10-15T12:00:00Z",
            "2026-10-15T24:00:00Z",
            "2026-10-15T23:60:00Z",
            "2026-10-15T23:59:60Z",
            "2026-10-15T12:00:00+00:00",
            "2026-02-30T12:00:00Z",
            "0000-01-01T00:00:00Z",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                packet["as_of_utc"] = value
                reviewer.review(encoded(packet))

    def test_reject_nonfinite_null_bytes_and_trailing_json(self):
        raw = encoded(document())
        for value in (
            raw.replace(b'"horizon_hours":24', b'"horizon_hours":NaN'),
            raw.replace(b'"horizon_hours":24', b'"horizon_hours":Infinity'),
            raw + b' {}',
            b"\x00" + raw,
            raw[:-1],
        ):
            with self.subTest(value=value[:15]), self.assertRaises(ValueError):
                reviewer.review(value)

    def test_reject_unbounded_cohort_and_transport(self):
        packet = document()
        for windows in ([], packet["windows"] * 9, {}, None):
            with self.subTest(length=len(windows) if isinstance(windows, list) else -1):
                packet["windows"] = windows
                with self.assertRaises(ValueError):
                    reviewer.review(encoded(packet))
        with self.assertRaises(ValueError):
            reviewer.review(b"x" * (reviewer.MAX_INPUT_BYTES + 1))
        with self.assertRaises(ValueError):
            reviewer.review(bytearray(encoded(document())))

    def test_no_network_or_system_clock_needed_in_review(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network")):
            with mock.patch.object(reviewer, "datetime", wraps=reviewer.datetime) as dt:
                dt.now.side_effect = AssertionError("clock")
                result = reviewer.review(encoded(document()))
                self.assertEqual(result["status"], "REVIEW_ONLY")
                self.assertNoAuthority(result)

    def test_real_subprocess_review_exit_is_nonzero(self):
        status, result, stderr = subprocess_review(encoded(document()))
        self.assertEqual(status, 3)
        self.assertEqual(stderr, b"")
        self.assertNoAuthority(result)
        self.assertEqual(result["current_later"], 1)

    def test_real_subprocess_atomic_hold_and_opaque_output(self):
        packet = encoded(document()).replace(
            b'"valid_until":"2026-10-14T00:00:00Z"',
            b'"valid_until":"customer-secret.invalid"',
        )
        status, result, stderr = subprocess_review(packet)
        self.assertEqual(status, 2)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(set(result), {"status", *reviewer.DENIAL_FLAGS})
        self.assertNotIn("customer-secret", json.dumps(result))
        self.assertEqual(stderr, b"")
        self.assertNoAuthority(result)

    def test_real_subprocess_size_argument_and_privacy_fail_closed(self):
        for payload, args in (
            (b"x" * (reviewer.MAX_INPUT_BYTES + 1), ()),
            (encoded(document()), ("--allow",)),
            (b"", ()),
        ):
            with self.subTest(args=args, size=len(payload)):
                status, result, stderr = subprocess_review(payload, *args)
                self.assertEqual(status, 2)
                self.assertEqual(result["status"], "HOLD")
                self.assertNoAuthority(result)
                self.assertEqual(stderr, b"")


    def test_real_authorization_grant_window_semantics_match_126_synthetic_cases(self):
        """Cross-check expiry claims against the actual immutable grant model."""
        from datetime import datetime, timedelta, timezone
        from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition

        anchor = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)

        def utc(value):
            return value.strftime("%Y-%m-%dT%H:%M:%SZ")

        case_count = 0
        for start_hours in (-48, -2, -1, 0, 1, 48):
            for duration_hours in (1, 2, 72):
                start = anchor + timedelta(hours=start_hours)
                end = start + timedelta(hours=duration_hours)
                grant = AuthorizationGrant(
                    grant_id="synthetic-only",
                    client_id="synthetic-only",
                    engagement_id="synthetic-only",
                    approved_by="fictional-operator",
                    reference="offline-fixture",
                    scope=ScopeDefinition(assets=(), max_risk=RiskLevel.ANALYSIS_ONLY),
                    valid_from=start,
                    valid_until=end,
                )
                for as_of_hours in (-72, -2, -1, 0, 1, 2, 72):
                    as_of = anchor + timedelta(hours=as_of_hours)
                    packet = {
                        "as_of_utc": utc(as_of),
                        "horizon_hours": 24,
                        "windows": [{"valid_from": utc(start),
                                     "valid_until": utc(end)}],
                    }
                    receipt = reviewer.review(encoded(packet))
                    self.assertNoAuthority(receipt)
                    self.assertEqual(receipt["status"], "REVIEW_ONLY")
                    current = grant.is_current(now=as_of)
                    self.assertEqual(
                        current,
                        (receipt["current_expiring_within_horizon"] == 1 or
                         receipt["current_later"] == 1),
                    )
                    self.assertEqual(receipt["not_yet_started"], int(as_of < start))
                    self.assertEqual(receipt["expired"], int(as_of > end))
                    case_count += 1
        self.assertEqual(case_count, 126)

    def test_full_32_window_cohort_and_atomic_last_member_rejection(self):
        packet = document()
        packet["windows"] = [packet["windows"][2].copy() for _ in range(32)]
        receipt = reviewer.review(encoded(packet))
        self.assertEqual(receipt["current_expiring_within_horizon"], 32)
        self.assertEqual(receipt["expired"], 0)
        self.assertNoAuthority(receipt)
        packet["windows"][-1]["valid_until"] = "2026-10-14T00:00:00Z"
        status, hold, stderr = subprocess_review(encoded(packet))
        self.assertEqual(status, 2)
        self.assertEqual(hold["status"], "HOLD")
        self.assertEqual(set(hold), {"status", *reviewer.DENIAL_FLAGS})
        self.assertNoAuthority(hold)
        self.assertEqual(stderr, b"")

    def test_max_calendar_timestamp_does_not_overflow_expiry_horizon(self):
        packet = {
            "as_of_utc": "9999-12-31T23:59:58Z",
            "horizon_hours": 720,
            "windows": [{
                "valid_from": "9999-12-30T00:00:00Z",
                "valid_until": "9999-12-31T23:59:59Z",
            }],
        }
        result = reviewer.review(encoded(packet))
        self.assertEqual(result["current_expiring_within_horizon"], 1)
        self.assertNoAuthority(result)


    def test_deeply_nested_json_cannot_escape_generic_hold(self):
        """A 16KiB nested packet must not dump a Python traceback or input."""
        payload = b"[" * 1500 + b"0" + b"]" * 1500
        code, result, stderr = subprocess_review(payload)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(set(result), {"status", *reviewer.DENIAL_FLAGS})
        self.assertNoAuthority(result)
        self.assertEqual(stderr, b"")

    def test_non_utf8_input_has_opaque_hold_without_traceback(self):
        payload = bytes([0xFF])
        code, result, stderr = subprocess_review(payload)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "HOLD")
        self.assertNoAuthority(result)
        self.assertEqual(stderr, b"")



    def test_open_pipe_without_eof_cannot_keep_cli_alive(self):
        """Even a completely valid JSON prefix is HOLD without timely EOF."""
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        )
        try:
            started = time.monotonic()
            proc.stdin.write(encoded(document()))
            proc.stdin.flush()  # Deliberately NEVER close the writer here.
            status = proc.wait(timeout=4.5)
            elapsed = time.monotonic() - started
            output = proc.stdout.read()
            error = proc.stderr.read()
            self.assertEqual(status, 2)
            self.assertLess(elapsed, 4.5)
            self.assertEqual(error, b"")
            receipt = json.loads(output.decode("ascii"))
            self.assertEqual(receipt["status"], "HOLD")
            self.assertEqual(set(receipt), {"status", *reviewer.DENIAL_FLAGS})
            self.assertNoAuthority(receipt)
            self.assertEqual(len(output.splitlines()), 1)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()

    def test_local_unix_socket_stdin_is_never_admitted(self):
        """No socket I/O is trusted as an offline packet, even over AF_UNIX."""
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        with socket.socketpair() as (reader, writer):
            writer.sendall(encoded(document()))
            writer.shutdown(socket.SHUT_WR)
            proc = subprocess.run(
                cmd, stdin=reader, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=5,
            )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, b"")
        receipt = json.loads(proc.stdout.decode("ascii"))
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(set(receipt), {"status", *reviewer.DENIAL_FLAGS})
        self.assertNoAuthority(receipt)

    def test_staged_regular_file_fd0_valid_control(self):
        """A local fixture supplied through fd0, not an input pathname, works."""
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        with tempfile.TemporaryFile(mode="w+b") as fixture:
            fixture.write(encoded(document()))
            fixture.seek(0)
            proc = subprocess.run(
                cmd, stdin=fixture, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=5,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stderr, b"")
        receipt = json.loads(proc.stdout.decode("ascii"))
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["expired"], 1)
        self.assertNoAuthority(receipt)


if __name__ == "__main__":
    unittest.main()
