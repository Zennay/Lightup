"""Synthetic-only API/subprocess security tests for an offline MAC tip receipt."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from lightup.scope_audit_anchor_auth_offline import (
    BODY_FIELDS, DOMAIN, MAX_BYTES, SCHEMA,
    compute_mac, verify_attestation,
)

KEY = b"not-a-real-key-for-fictional-tests-only-2026"
OTHER_KEY = b"different-fictional-key-for-tests-only-2026"
ID = "fictional-review-signer-01"
NOW = datetime(2026, 10, 17, 16, 30, tzinfo=timezone.utc)


def timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def receipt(*, issued=NOW - timedelta(minutes=5), expires=NOW + timedelta(minutes=5)):
    body = {
        "schema": SCHEMA,
        "key_id": ID,
        "tip_sha256": "a" * 64,
        "nonce": "b" * 32,
        "issued_at": timestamp(issued),
        "expires_at": timestamp(expires),
    }
    return {**body, "mac_sha256": compute_mac(body, KEY)}


def encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class ScopeAuditAnchorAuthTests(unittest.TestCase):
    def assert_hold(self, raw, key=KEY, now=NOW, expected_key=ID):
        actual = verify_attestation(raw, key, now, expected_key)
        self.assertEqual("HOLD", actual["status"])
        self.assertEqual("MAC_INVALID", actual["reason"])
        self.assertEqual(
            set(actual),
            {"status", "reason", "consent_verified", "authorization_granted", "release_approved"},
        )
        for name in ("consent_verified", "authorization_granted", "release_approved"):
            self.assertIs(actual[name], False)

    def test_valid_fictional_tip_is_only_review(self):
        signed = encode(receipt())
        result = verify_attestation(signed, KEY, NOW, ID)
        self.assertEqual("REVIEW_ONLY", result["status"])
        self.assertEqual("FICTIONAL_MAC_ONLY", result["reason"])
        self.assertIs(result["consent_verified"], False)
        self.assertIs(result["authorization_granted"], False)
        self.assertIs(result["release_approved"], False)

    def test_wrong_key_does_not_verify_mac(self):
        self.assert_hold(encode(receipt()), OTHER_KEY)

    def test_missing_and_wrong_pinned_key_identity(self):
        self.assert_hold(encode(receipt()), expected_key="not-the-pinned-key")
        self.assert_hold(encode(receipt()), expected_key="")
        self.assert_hold(encode(receipt()), expected_key=True)

    def test_tamper_each_signed_field_rejected(self):
        substitutions = {
            "schema": "LIGHTUP-FICTIONAL-AUDIT-TIP-MAC-V0",
            "key_id": "different-signer",
            "tip_sha256": "f" * 64,
            "nonce": "c" * 32,
            "issued_at": "2026-10-17T16:21:00Z",
            "expires_at": "2026-10-17T16:40:00Z",
            "mac_sha256": "e" * 64,
        }
        for field, invalid in substitutions.items():
            with self.subTest(field=field):
                record = receipt()
                record[field] = invalid
                self.assert_hold(encode(record))

    def test_expired_expiry_and_invalid_duration_denied_even_with_valid_mac(self):
        intervals = [
            (NOW - timedelta(hours=2), NOW - timedelta(seconds=1)),
            (NOW - timedelta(seconds=2), NOW),
            (NOW - timedelta(minutes=10), NOW - timedelta(minutes=10)),
            (NOW - timedelta(seconds=1), NOW + timedelta(days=2)),
            (NOW + timedelta(hours=1), NOW + timedelta(hours=2)),
        ]
        for issued, expires in intervals:
            with self.subTest(issued=issued, expires=expires):
                self.assert_hold(encode(receipt(issued=issued, expires=expires)))

    def test_five_minute_clock_skew_is_not_permanent_authority(self):
        signed = receipt(issued=NOW + timedelta(minutes=4), expires=NOW + timedelta(hours=1))
        self.assertEqual(
            "REVIEW_ONLY",
            verify_attestation(encode(signed), KEY, NOW, ID)["status"],
        )
        self.assert_hold(
            encode(receipt(issued=NOW + timedelta(minutes=6), expires=NOW + timedelta(hours=1))),
        )

    def test_exact_24h_max_lifetime(self):
        self.assertEqual(
            "REVIEW_ONLY",
            verify_attestation(
                encode(receipt(issued=NOW, expires=NOW + timedelta(hours=24))),
                KEY, NOW, ID,
            )["status"],
        )
        self.assert_hold(
            encode(receipt(issued=NOW, expires=NOW + timedelta(hours=24, seconds=1)))
        )

    def test_schema_and_forged_authority_keys_denied(self):
        for key in ("authorization_granted", "client_consent", "release_approved"):
            with self.subTest(field=key):
                record = receipt()
                record[key] = True
                self.assert_hold(encode(record))

    def test_noncanonical_types_and_blank_or_unicode_ids(self):
        for key, invalid in (
            ("schema", False),
            ("key_id", True),
            ("key_id", "fictiøn"),
            ("key_id", ""),
            ("tip_sha256", "A" * 64),
            ("tip_sha256", False),
            ("nonce", "B" * 32),
            ("issued_at", 0),
            ("expires_at", None),
            ("mac_sha256", "g" * 64),
        ):
            with self.subTest(field=key, invalid=repr(invalid)):
                record = receipt()
                record[key] = invalid
                self.assert_hold(encode(record))

    def test_invalid_json_duplicate_keys_nonfinite_and_utf8(self):
        signed = encode(receipt())
        self.assert_hold(signed.replace(b'"schema":', b'"schema":"fake","schema":', 1))
        self.assert_hold(signed.replace(b'"schema":', b'"other":NaN,"schema":', 1))
        self.assert_hold(signed + b"\xff")
        self.assert_hold(b"")
        self.assert_hold(b"[]")
        self.assert_hold(b"{}")
        self.assert_hold(signed + b" " * MAX_BYTES)

    def test_exact_secret_type_and_length(self):
        signed = encode(receipt())
        for key in (None, "", b"", b"x" * 31, b"x" * 65, bytearray(KEY), True):
            with self.subTest(secret=str(type(key))):
                self.assert_hold(signed, key=key)

    def test_clock_type_and_timezone_fail_closed(self):
        signed = encode(receipt())
        for invalid in (
            None, "2026-10-17", NOW.replace(tzinfo=None),
            NOW.astimezone(timezone(timedelta(hours=1))),
            True,
        ):
            with self.subTest(clock=repr(invalid)):
                self.assert_hold(signed, now=invalid)

    def test_mac_has_domain_separation_and_deterministic_canonical_body(self):
        body = {key: receipt()[key] for key in BODY_FIELDS}
        a = compute_mac(body, KEY)
        b = compute_mac(dict(reversed(list(body.items()))), KEY)
        self.assertEqual(a, b)
        import hashlib
        import hmac
        naive = hmac.new(KEY, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        self.assertNotEqual(a, naive)
        self.assertTrue(DOMAIN.endswith(b"\x00"))

    def _cli(self, data, key=KEY, *, synthetic=True):
        root = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(root / "src")
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, key)
            os.close(write_fd)
            write_fd = -1
            command = [
                sys.executable, "-m", "lightup.scope_audit_anchor_auth_offline",
                "--expected-key-id", ID,
                "--key-fd", str(read_fd),
            ]
            if synthetic:
                command.append("--synthetic-only")
            return subprocess.run(
                command,
                cwd=root, env=environment, input=data, capture_output=True,
                pass_fds=(read_fd,), timeout=10,
            )
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def test_real_cli_with_inherited_key_fd_and_fresh_receipt(self):
        now = datetime.now(timezone.utc)
        record = receipt(
            issued=now - timedelta(minutes=2),
            expires=now + timedelta(minutes=8),
        )
        result = self._cli(encode(record))
        self.assertEqual(3, result.returncode, result.stderr.decode())
        output = json.loads(result.stdout)
        self.assertEqual("REVIEW_ONLY", output["status"])
        self.assertNotIn(KEY, result.stdout)
        self.assertNotIn(ID.encode(), result.stdout)
        self.assertNotIn(b"a" * 64, result.stdout)

    def test_real_cli_rejects_invalid_key_and_tampered_mac(self):
        now = datetime.now(timezone.utc)
        record = receipt(issued=now - timedelta(minutes=1),
                         expires=now + timedelta(minutes=1))
        for key in (b"too-short", OTHER_KEY):
            result = self._cli(encode(record), key=key)
            self.assertEqual(2, result.returncode)
            self.assertEqual("HOLD", json.loads(result.stdout)["status"])

    def test_real_cli_requires_explicit_synthetic_opt_in(self):
        now = datetime.now(timezone.utc)
        record = receipt(issued=now - timedelta(minutes=1),
                         expires=now + timedelta(minutes=1))
        result = self._cli(encode(record), synthetic=False)
        self.assertEqual(2, result.returncode)
        self.assertEqual("HOLD", json.loads(result.stdout)["status"])


    def test_real_cli_open_pipe_without_eof_fails_closed_within_seconds(self):
        now = datetime.now(timezone.utc)
        record = receipt(
            issued=now - timedelta(minutes=1),
            expires=now + timedelta(minutes=2),
        )
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        reader, writer = os.pipe()
        process = None
        try:
            os.write(writer, KEY)
            # Deliberately keep writer open: parent stalls the EOF boundary.
            # A safe CLI must terminate with generic HOLD without hanging.
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "lightup.scope_audit_anchor_auth_offline",
                    "--synthetic-only", "--expected-key-id", ID,
                    "--key-fd", str(reader),
                ],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, pass_fds=(reader,),
                cwd=root, env=env,
            )
            output, errors = process.communicate(input=encode(record), timeout=8)
            self.assertEqual(2, process.returncode, errors.decode())
            self.assertEqual("HOLD", json.loads(output)["status"])
            self.assertNotIn(KEY, output)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            os.close(reader)
            os.close(writer)

    def test_socket_descriptor_is_not_a_synthetic_key_source(self):
        import socket
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        now = datetime.now(timezone.utc)
        record = receipt(
            issued=now - timedelta(minutes=1),
            expires=now + timedelta(minutes=2),
        )
        left, right = socket.socketpair()
        try:
            result = subprocess.run(
                [
                    sys.executable, "-m", "lightup.scope_audit_anchor_auth_offline",
                    "--synthetic-only", "--expected-key-id", ID,
                    "--key-fd", str(left.fileno()),
                ],
                input=encode(record), capture_output=True,
                pass_fds=(left.fileno(),), cwd=root, env=env, timeout=7,
            )
            self.assertEqual(2, result.returncode)
            self.assertEqual("HOLD", json.loads(result.stdout)["status"])
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
