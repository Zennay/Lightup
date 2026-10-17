"""Synthetic HMAC batch replay, duplicate and subprocess admission tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from lightup.scope_audit_anchor_auth_offline import (
    SCHEMA as RECEIPT_SCHEMA,
    compute_mac,
)
from lightup.scope_audit_anchor_batch_offline import (
    MAX_BATCH_BYTES, SCHEMA, verify_batch,
)

SECRET = b"fictional-key-for-batch-tests-only-2026"
ALT_SECRET = b"wrong-key-for-fictional-batch-only-2026"
KEY_ID = "fictional-batch-checker"


def make_receipts(count: int, now: datetime):
    receipts = []
    issued = now - timedelta(minutes=40)
    for i in range(count):
        body = {
            "schema": RECEIPT_SCHEMA,
            "key_id": KEY_ID,
            "tip_sha256": format(i + 1, "064x"),
            "nonce": format(i + 1, "032x"),
            "issued_at": (issued + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(minutes=8)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        receipts.append({**body, "mac_sha256": compute_mac(body, SECRET)})
    return receipts


def envelope(items):
    return {"schema": SCHEMA, "attestations": items}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def resign(item):
    body = {k: v for k, v in item.items() if k != "mac_sha256"}
    item["mac_sha256"] = compute_mac(body, SECRET)


class ScopeAuditAnchorBatchTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 17, 16, 30, tzinfo=timezone.utc)

    def assert_hold(self, raw, key=SECRET, key_id=KEY_ID):
        if type(raw) is not bytes:
            raw = encode(raw)
        result = verify_batch(raw, key, self.now, key_id)
        self.assertEqual("HOLD", result["status"])
        self.assertEqual("BATCH_INVALID", result["reason"])
        self.assertEqual(0, result["records"])
        for field in ("consent_verified", "authorization_granted", "release_approved"):
            self.assertIs(result[field], False)

    def test_single_receipt_is_review_only(self):
        raw = encode(envelope(make_receipts(1, self.now)))
        receipt = verify_batch(raw, SECRET, self.now, KEY_ID)
        self.assertEqual("REVIEW_ONLY", receipt["status"])
        self.assertEqual(1, receipt["records"])
        self.assertIs(receipt["authorization_granted"], False)

    def test_multiple_receipts_strict_order(self):
        raw = encode(envelope(make_receipts(5, self.now)))
        self.assertEqual(5, verify_batch(raw, SECRET, self.now, KEY_ID)["records"])

    def test_32_receipt_maximum(self):
        raw = encode(envelope(make_receipts(32, self.now)))
        self.assertEqual(32, verify_batch(raw, SECRET, self.now, KEY_ID)["records"])

    def test_33_receipts_hold(self):
        self.assert_hold(envelope(make_receipts(33, self.now)))

    def test_duplicate_nonce_resigned_does_not_bypass(self):
        items = make_receipts(2, self.now)
        items[1]["nonce"] = items[0]["nonce"]
        resign(items[1])
        self.assert_hold(envelope(items))

    def test_duplicate_tip_resigned_does_not_bypass(self):
        items = make_receipts(2, self.now)
        items[1]["tip_sha256"] = items[0]["tip_sha256"]
        resign(items[1])
        self.assert_hold(envelope(items))

    def test_replay_full_signed_record_holds(self):
        items = make_receipts(2, self.now)
        items.append(dict(items[-1]))
        self.assert_hold(envelope(items))

    def test_valid_signed_but_reordered_holds(self):
        items = make_receipts(3, self.now)
        items[1], items[2] = items[2], items[1]
        self.assert_hold(envelope(items))

    def test_equal_issued_at_even_with_new_mac_holds(self):
        items = make_receipts(2, self.now)
        items[1]["issued_at"] = items[0]["issued_at"]
        resign(items[1])
        self.assert_hold(envelope(items))

    def test_each_position_bad_mac_32_cases(self):
        for index in range(32):
            with self.subTest(index=index):
                items = make_receipts(32, self.now)
                items[index]["mac_sha256"] = "f" * 64
                self.assert_hold(envelope(items))

    def test_each_position_forged_authority_field_32_cases(self):
        for index in range(32):
            with self.subTest(index=index):
                items = make_receipts(32, self.now)
                items[index]["consent_verified"] = True
                self.assert_hold(envelope(items))

    def test_bad_secret_and_identity(self):
        raw = envelope(make_receipts(2, self.now))
        self.assert_hold(raw, key=ALT_SECRET)
        self.assert_hold(raw, key_id="other-client")
        self.assert_hold(raw, key=b"bad")

    def test_duplicate_json_key_bad_utf8_and_nonfinite(self):
        raw = encode(envelope(make_receipts(2, self.now)))
        self.assert_hold(raw.replace(b'"schema":', b'"schema":"bad","schema":', 1))
        self.assert_hold(raw.replace(b'"schema":', b'"float":NaN,"schema":', 1))
        self.assert_hold(raw + b"\xff")

    def test_root_rejects_forged_permission(self):
        root = envelope(make_receipts(1, self.now))
        root["release_approved"] = True
        self.assert_hold(root)

    def test_size_and_empty_rejection(self):
        raw = encode(envelope(make_receipts(1, self.now)))
        self.assert_hold(raw + b" " * MAX_BATCH_BYTES)
        self.assert_hold(b"")
        self.assert_hold(b"[]")
        self.assert_hold(envelope([]))

    def _cli(self, raw, key=SECRET, synthetic=True):
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        reader, writer = os.pipe()
        try:
            os.write(writer, key)
            os.close(writer)
            writer = -1
            argv = [
                sys.executable, "-m", "lightup.scope_audit_anchor_batch_offline",
                "--expected-key-id", KEY_ID, "--key-fd", str(reader),
            ]
            if synthetic:
                argv.append("--synthetic-only")
            return subprocess.run(
                argv, input=raw, capture_output=True, cwd=root,
                env=env, pass_fds=(reader,), timeout=10,
            )
        finally:
            os.close(reader)
            if writer >= 0:
                os.close(writer)

    def test_real_cli_inherited_fd_review_no_leak(self):
        now = datetime.now(timezone.utc)
        raw = encode(envelope(make_receipts(4, now)))
        p = self._cli(raw)
        self.assertEqual(3, p.returncode, p.stderr.decode())
        self.assertEqual("REVIEW_ONLY", json.loads(p.stdout)["status"])
        self.assertNotIn(SECRET, p.stdout)
        self.assertNotIn(KEY_ID.encode(), p.stdout)
        self.assertNotIn(b"nonce", p.stdout)

    def test_real_cli_wrong_key_and_missing_opt_in_hold(self):
        now = datetime.now(timezone.utc)
        raw = encode(envelope(make_receipts(1, now)))
        for p in (self._cli(raw, ALT_SECRET), self._cli(raw, synthetic=False)):
            with self.subTest(exit=p.returncode):
                self.assertEqual(2, p.returncode)
                self.assertEqual("HOLD", json.loads(p.stdout)["status"])


if __name__ == "__main__":
    unittest.main()
