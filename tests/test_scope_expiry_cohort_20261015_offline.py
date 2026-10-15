"""Offline, genuine subprocess regressions for untrusted expiry cohort review."""
from __future__ import annotations

import json
import os
import socket
import stat
from types import SimpleNamespace
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
        reader, writer = socket.socketpair()
        with reader, writer:
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


    def test_regular_file_output_sink_refused_without_creating_receipt(self):
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        with tempfile.TemporaryFile(mode="w+b") as sink:
            proc = subprocess.run(
                cmd, input=encoded(document()), stdout=sink,
                stderr=subprocess.PIPE, check=False, timeout=5,
            )
            sink.seek(0)
            self.assertEqual(sink.read(), b"")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, b"")

    def test_local_unix_socket_output_sink_refused_without_data(self):
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        reader, writer = socket.socketpair()
        with reader, writer:
            proc = subprocess.run(
                cmd, input=encoded(document()), stdout=writer,
                stderr=subprocess.PIPE, check=False, timeout=5,
            )
            writer.close()
            self.assertEqual(reader.recv(1024), b"")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, b"")

    def test_closed_output_pipe_fails_nonzero_without_traceback(self):
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            proc.stdout.close()  # Deliberately remove the sole pipe reader.
            proc.stdin.write(encoded(document()))
            proc.stdin.close()
            status = proc.wait(timeout=5)
            self.assertEqual(status, 2)
            self.assertEqual(proc.stderr.read(), b"")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            proc.stderr.close()

    def test_filled_output_pipe_refused_without_waiting_for_reader(self):
        """Never await a full pipe's consumer while emitting non-authority."""
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        read_fd, write_fd = os.pipe()
        try:
            os.set_blocking(write_fd, False)
            filled = 0
            for _ in range(256):
                try:
                    filled += os.write(write_fd, b"x" * 4096)
                except BlockingIOError:
                    break
            self.assertGreater(filled, 0)
            started = time.monotonic()
            proc = subprocess.run(
                cmd, input=encoded(document()), stdout=write_fd,
                stderr=subprocess.PIPE, check=False, timeout=5,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stderr, b"")
            self.assertLess(time.monotonic() - started, 4.5)
        finally:
            os.close(write_fd)
            os.close(read_fd)


    def test_fd0_fd1_original_blocking_flags_restored_after_real_process(self):
        """FD mode changes must not survive success OR malformed input HOLD."""
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        for raw, expected in ((encoded(document()), 3),
                              (b'{"incomplete":', 2)):
            with self.subTest(expected=expected):
                input_read, input_write = os.pipe()
                output_read, output_write = os.pipe()
                proc = None
                try:
                    self.assertTrue(os.get_blocking(input_read))
                    self.assertTrue(os.get_blocking(output_write))
                    proc = subprocess.Popen(
                        cmd, stdin=input_read, stdout=output_write,
                        stderr=subprocess.PIPE,
                    )
                    os.write(input_write, raw)
                    os.close(input_write)
                    input_write = -1
                    self.assertEqual(proc.wait(timeout=5), expected)
                    self.assertTrue(os.get_blocking(input_read))
                    self.assertTrue(os.get_blocking(output_write))
                    os.close(output_write)
                    output_write = -1
                    receipt = json.loads(os.read(output_read, 4096).decode("ascii"))
                    self.assertEqual(
                        receipt["status"],
                        "REVIEW_ONLY" if expected == 3 else "HOLD",
                    )
                    self.assertNoAuthority(receipt)
                    self.assertEqual(proc.stderr.read(), b"")
                finally:
                    if proc is not None:
                        if proc.poll() is None:
                            proc.kill()
                            proc.wait(timeout=2)
                        proc.stderr.close()
                    for fd in (input_read, input_write, output_read, output_write):
                        if fd >= 0:
                            os.close(fd)


    def test_regular_file_nonzero_offset_denied_atomically(self):
        """A valid suffix is not a complete immutable review packet."""
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        with tempfile.TemporaryFile(mode="w+b") as fixture:
            fixture.write(encoded(document()))
            fixture.seek(1)
            proc = subprocess.run(
                cmd, stdin=fixture, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, check=False,
            )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, b"")
        receipt = json.loads(proc.stdout.decode("ascii"))
        self.assertEqual(set(receipt), {"status", *reviewer.DENIAL_FLAGS})
        self.assertEqual(receipt["status"], "HOLD")
        self.assertNoAuthority(receipt)

    def test_regular_file_zero_length_and_oversized_preflight(self):
        """Reject bad declared file sizes before reading a suffix or huge file."""
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        for payload in (b"", b" " * (reviewer.MAX_INPUT_BYTES + 1)):
            with self.subTest(size=len(payload)):
                with tempfile.TemporaryFile(mode="w+b") as fixture:
                    fixture.write(payload)
                    fixture.seek(0)
                    proc = subprocess.run(
                        cmd, stdin=fixture, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=5, check=False,
                    )
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stderr, b"")
                receipt = json.loads(proc.stdout.decode("ascii"))
                self.assertEqual(receipt["status"], "HOLD")
                self.assertNoAuthority(receipt)

    def test_regular_file_mutation_during_read_is_hold(self):
        """Pinned regular file must detect changed mtime after EOF."""
        initial = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_dev=8, st_ino=10,
            st_size=2, st_mtime_ns=10, st_ctime_ns=11,
        )
        changed = SimpleNamespace(
            st_mode=initial.st_mode, st_dev=initial.st_dev,
            st_ino=initial.st_ino, st_size=2,
            st_mtime_ns=12, st_ctime_ns=11,
        )
        with mock.patch.object(reviewer.sys, "stdin") as stdin, \
                mock.patch.object(reviewer.os, "fstat", side_effect=[
                    initial, initial, initial, initial,
                    initial, initial, initial, changed,
                ]), \
                mock.patch.object(reviewer.os, "dup", return_value=73) as dup, \
                mock.patch.object(reviewer.os, "close") as close, \
                mock.patch.object(reviewer.os, "lseek", return_value=0), \
                mock.patch.object(reviewer.os, "get_blocking", return_value=True), \
                mock.patch.object(reviewer.os, "set_blocking") as blocking, \
                mock.patch.object(reviewer.select, "select",
                                  return_value=([73], [], [])), \
                mock.patch.object(reviewer.os, "read",
                                  side_effect=[b"{}", b""]) as read:
            stdin.fileno.return_value = 0
            with self.assertRaises(ValueError):
                reviewer._read_bounded_stdin()
            dup.assert_called_once_with(0)
            self.assertEqual([call.args[0] for call in read.call_args_list],
                             [73, 73])
            close.assert_called_once_with(73)
            self.assertEqual(blocking.call_args_list, [
                mock.call(73, False), mock.call(73, True),
            ])

    def test_stdin_descriptor_identity_swap_is_hold_before_read(self):
        original = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600,
                                   st_dev=8, st_ino=10)
        swapped = SimpleNamespace(st_mode=original.st_mode,
                                  st_dev=8, st_ino=11)
        with mock.patch.object(reviewer.sys, "stdin") as stdin, \
                mock.patch.object(reviewer.os, "fstat",
                                  side_effect=[original, original,
                                               swapped, original]), \
                mock.patch.object(reviewer.os, "dup", return_value=73) as dup, \
                mock.patch.object(reviewer.os, "close") as close, \
                mock.patch.object(reviewer.os, "get_blocking", return_value=True), \
                mock.patch.object(reviewer.os, "set_blocking") as blocking, \
                mock.patch.object(reviewer.select, "select",
                                  return_value=([73], [], [])), \
                mock.patch.object(reviewer.os, "read") as read:
            stdin.fileno.return_value = 0
            with self.assertRaises(ValueError):
                reviewer._read_bounded_stdin()
            dup.assert_called_once_with(0)
            read.assert_not_called()
            close.assert_called_once_with(73)
            self.assertEqual(blocking.call_args_list, [
                mock.call(73, False), mock.call(73, True),
            ])

    def test_stdin_pin_prevents_unsafe_original_fd0_read(self):
        original = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600,
                                   st_dev=8, st_ino=10)
        with mock.patch.object(reviewer.sys, "stdin") as stdin, \
                mock.patch.object(reviewer.os, "fstat", return_value=original), \
                mock.patch.object(reviewer.os, "dup", return_value=73) as dup, \
                mock.patch.object(reviewer.os, "close") as close, \
                mock.patch.object(reviewer.os, "get_blocking", return_value=True), \
                mock.patch.object(reviewer.os, "set_blocking") as blocking, \
                mock.patch.object(reviewer.select, "select",
                                  return_value=([73], [], [])) as selected, \
                mock.patch.object(reviewer.os, "read",
                                  side_effect=[b"{}", b""]) as read:
            stdin.fileno.return_value = 0
            self.assertEqual(reviewer._read_bounded_stdin(), b"{}")
            dup.assert_called_once_with(0)
            self.assertEqual([call.args[0] for call in read.call_args_list],
                             [73, 73])
            self.assertEqual([call.args[0][0] for call in
                              selected.call_args_list], [[73], [73]])
            close.assert_called_once_with(73)
            self.assertEqual(blocking.call_args_list, [
                mock.call(73, False), mock.call(73, True),
            ])

    def test_stdin_pin_mismatch_closes_without_read_or_mode_change(self):
        original = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600,
                                   st_dev=8, st_ino=10)
        wrong = SimpleNamespace(st_mode=original.st_mode,
                                st_dev=8, st_ino=12)
        with mock.patch.object(reviewer.sys, "stdin") as stdin, \
                mock.patch.object(reviewer.os, "fstat",
                                  side_effect=[original, wrong]), \
                mock.patch.object(reviewer.os, "dup", return_value=73), \
                mock.patch.object(reviewer.os, "close") as close, \
                mock.patch.object(reviewer.os, "set_blocking") as blocking, \
                mock.patch.object(reviewer.os, "read") as read:
            stdin.fileno.return_value = 0
            with self.assertRaises(ValueError):
                reviewer._read_bounded_stdin()
            read.assert_not_called()
            blocking.assert_not_called()
            close.assert_called_once_with(73)

    def test_stdout_descriptor_identity_swap_never_writes(self):
        original = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600,
                                   st_dev=8, st_ino=10)
        swapped = SimpleNamespace(st_mode=original.st_mode,
                                  st_dev=8, st_ino=11)
        with mock.patch.object(reviewer.sys, "stdout") as stdout, \
                mock.patch.object(reviewer.os, "fstat",
                                  side_effect=[original, original, original, swapped]), \
                mock.patch.object(reviewer.os, "dup", return_value=71) as dup, \
                mock.patch.object(reviewer.os, "close") as close, \
                mock.patch.object(reviewer.os, "get_blocking", return_value=True), \
                mock.patch.object(reviewer.os, "set_blocking") as blocking, \
                mock.patch.object(reviewer.os, "write") as write:
            stdout.fileno.return_value = 1
            self.assertFalse(reviewer._emit_receipt(reviewer._receipt("HOLD")))
            dup.assert_called_once_with(1)
            write.assert_not_called()
            close.assert_called_once_with(71)
            self.assertEqual(blocking.call_args_list, [
                mock.call(71, False), mock.call(71, True),
            ])

    def test_stdout_receipt_always_writes_pinned_descriptor_not_fd1(self):
        original = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600,
                                   st_dev=8, st_ino=10)
        receipt = reviewer._receipt("HOLD")
        with mock.patch.object(reviewer.sys, "stdout") as stdout, \
                mock.patch.object(reviewer.os, "fstat", return_value=original), \
                mock.patch.object(reviewer.os, "dup", return_value=71) as dup, \
                mock.patch.object(reviewer.os, "close") as close, \
                mock.patch.object(reviewer.os, "get_blocking", return_value=True), \
                mock.patch.object(reviewer.os, "set_blocking") as blocking, \
                mock.patch.object(reviewer.os, "write") as write:
            stdout.fileno.return_value = 1
            write.side_effect = lambda fd, payload: len(payload)
            self.assertTrue(reviewer._emit_receipt(receipt))
            dup.assert_called_once_with(1)
            self.assertEqual(write.call_count, 1)
            self.assertEqual(write.call_args.args[0], 71)
            self.assertNotEqual(write.call_args.args[0], 1)
            close.assert_called_once_with(71)
            self.assertEqual(blocking.call_args_list, [
                mock.call(71, False), mock.call(71, True),
            ])

    def test_stdout_write_error_does_not_leak_or_keep_pinned_fd_open(self):
        original = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600,
                                   st_dev=8, st_ino=10)
        with mock.patch.object(reviewer.sys, "stdout") as stdout, \
                mock.patch.object(reviewer.os, "fstat", return_value=original), \
                mock.patch.object(reviewer.os, "dup", return_value=71), \
                mock.patch.object(reviewer.os, "close") as close, \
                mock.patch.object(reviewer.os, "get_blocking", return_value=True), \
                mock.patch.object(reviewer.os, "set_blocking") as blocking, \
                mock.patch.object(reviewer.os, "write",
                                  side_effect=BrokenPipeError("synthetic pipe")) as write:
            stdout.fileno.return_value = 1
            self.assertFalse(reviewer._emit_receipt(reviewer._receipt("HOLD")))
            write.assert_called_once()
            self.assertEqual(write.call_args.args[0], 71)
            close.assert_called_once_with(71)
            self.assertEqual(blocking.call_args_list, [
                mock.call(71, False), mock.call(71, True),
            ])

    def test_output_receipt_only_accepts_literal_false_flags(self):
        valid = reviewer.review(encoded(document()))
        self.assertTrue(reviewer._receipt_is_safe(valid))
        for key in reviewer.DENIAL_FLAGS:
            for spoof in (True, 0, 1, "false", "no", None):
                with self.subTest(key=key, spoof=spoof):
                    forged = {**valid, key: spoof}
                    self.assertFalse(reviewer._receipt_is_safe(forged))
                    self.assertFalse(reviewer._emit_receipt(forged))

    def test_output_receipt_rejects_claimed_approvals_and_sensitive_fields(self):
        valid = reviewer.review(encoded(document()))
        self.assertTrue(reviewer._receipt_is_safe(reviewer._receipt("HOLD")))
        cases = [
            {**valid, "status": "APPROVED"},
            {**valid, "status": True},
            {**valid, "status": "PASS"},
            {**valid, "client": "fixture.client.invalid"},
            {**valid, "target": "fixture.invalid"},
            {**valid, "authorization_verified": True},
            {**reviewer._receipt("HOLD"), "expired": 1},
            {"status": "HOLD"},
            {**valid, "expired": -1},
            {**valid, "expired": 33},
            {**valid, "expired": True},
            {**valid, "expired": 1.0},
            {**valid, "expired": "1"},
            {**valid, "expired": 0, "not_yet_started": 0,
             "current_expiring_within_horizon": 0, "current_later": 0},
            {**valid, "expired": 32},
            [],
            None,
        ]
        for i, forged in enumerate(cases):
            with self.subTest(i=i):
                self.assertFalse(reviewer._receipt_is_safe(forged))
                self.assertFalse(reviewer._emit_receipt(forged))

    def test_output_receipt_accepts_full_cohort_without_creating_authority(self):
        result = reviewer.review(encoded({
            "as_of_utc": "2026-10-15T12:00:00Z",
            "horizon_hours": 1,
            "windows": [
                {"valid_from": "2026-10-15T11:00:00Z",
                 "valid_until": "2026-10-15T12:01:00Z"}
                for _ in range(32)
            ],
        }))
        self.assertEqual(result["current_expiring_within_horizon"], 32)
        self.assertTrue(reviewer._receipt_is_safe(result))
        self.assertNoAuthority(result)


    def test_utc_expiry_results_ignore_host_timezone_at_dst_boundaries(self):
        """Actual subprocess output may not change with OS TZ or DST folds."""
        cmd = [sys.executable, str(ROOT / "scripts" /
                                  "review_scope_expiry_cohort_20261015_offline.py")]
        cases = [
            ("2026-03-29T01:00:00Z",
             "2026-03-29T00:30:00Z", "2026-03-29T01:30:00Z"),
            ("2026-10-25T01:00:00Z",
             "2026-10-25T00:30:00Z", "2026-10-25T01:30:00Z"),
        ]
        for instant, start, end in cases:
            packet = encoded({
                "as_of_utc": instant,
                "horizon_hours": 1,
                "windows": [{"valid_from": start, "valid_until": end}],
            })
            original = None
            for timezone in ("UTC", "Europe/London", "Pacific/Kiritimati",
                             "America/New_York"):
                with self.subTest(instant=instant, timezone=timezone):
                    proc = subprocess.run(
                        cmd, input=packet, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=5, check=False,
                        env={**os.environ, "TZ": timezone},
                    )
                    self.assertEqual(proc.returncode, 3)
                    self.assertEqual(proc.stderr, b"")
                    receipt = json.loads(proc.stdout.decode("ascii"))
                    self.assertEqual(receipt["current_expiring_within_horizon"], 1)
                    self.assertNoAuthority(receipt)
                    if original is None:
                        original = proc.stdout
                    else:
                        self.assertEqual(proc.stdout, original)


if __name__ == "__main__":
    unittest.main()
