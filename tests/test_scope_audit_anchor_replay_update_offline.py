"""Real negative regression corpus for externally anchored fictional MAC replay ledgers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from lightup.scope_audit_anchor_auth_offline import (
    SCHEMA as RECEIPT_SCHEMA, compute_mac,
)
from lightup.scope_audit_anchor_batch_offline import SCHEMA as BATCH_SCHEMA
from lightup.scope_audit_anchor_replay_update_offline import (
    SCHEMA, LEDGER_SCHEMA, MAX_UPDATE_BYTES, MAX_LEDGER_ENTRIES,
    compute_ledger_anchor, verify_replay_update,
)

KEY = b"fictional-ledger-hmac-key-no-client-or-human-data-2026"
OTHER = b"different-ledger-key-for-fictional-review-only-2026"
KEY_ID = "fake-ledger-test-key"
NOW = datetime(2026, 10, 17, 16, 30, tzinfo=timezone.utc)


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def date(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def entry(index, at):
    return {
        "nonce": format(index, "032x"),
        "tip_sha256": format(index, "064x"),
        "issued_at": date(at),
    }


def ledger(entries, key_id=KEY_ID):
    return {"schema": LEDGER_SCHEMA, "key_id": key_id, "entries": entries}


def signed(index, now=NOW):
    base = entry(index, now - timedelta(minutes=7) + timedelta(seconds=index))
    body = {
        **base, "schema": RECEIPT_SCHEMA, "key_id": KEY_ID,
        "expires_at": date(now + timedelta(minutes=10)),
    }
    return {**body, "mac_sha256": compute_mac(body, KEY)}


def fixture(old=2, added=(30, 31), now=NOW):
    previous = [
        entry(i + 1, now - timedelta(days=2) + timedelta(minutes=i))
        for i in range(old)
    ]
    incoming = [signed(i, now) for i in added]
    additions = [
        {field: value for field, value in receipt.items()
         if field in {"nonce", "tip_sha256", "issued_at"}}
        for receipt in incoming
    ]
    root = {
        "schema": SCHEMA,
        "before": ledger(previous),
        "after": ledger(previous + additions),
        "incoming": {"schema": BATCH_SCHEMA, "attestations": incoming},
    }
    return root, compute_ledger_anchor(root["before"])


class FictionalReplayLedgerTests(unittest.TestCase):
    def assert_hold(self, obj, tip, secret=KEY, now=NOW, key_id=KEY_ID):
        result = verify_replay_update(
            obj if type(obj) is bytes else encode(obj),
            tip, secret, now, key_id,
        )
        self.assertEqual("HOLD", result["status"])
        self.assertEqual(0, result["previous_records"])
        self.assertEqual(0, result["proposed_records"])
        self.assertEqual(0, result["appended_records"])
        self.assertEqual("REPLAY_UPDATE_INVALID", result["reason"])
        for flag in ("consent_verified", "authorization_granted", "release_approved"):
            self.assertIs(result[flag], False)

    def assert_review(self, obj, tip, old_count, next_count):
        receipt = verify_replay_update(encode(obj), tip, KEY, NOW, KEY_ID)
        self.assertEqual("REVIEW_ONLY", receipt["status"])
        self.assertEqual("FICTIONAL_REPLAY_CONTINUITY_ONLY", receipt["reason"])
        self.assertEqual(old_count, receipt["previous_records"])
        self.assertEqual(next_count, receipt["proposed_records"])
        self.assertEqual(next_count - old_count, receipt["appended_records"])
        for flag in ("consent_verified", "authorization_granted", "release_approved"):
            self.assertIs(receipt[flag], False)

    def test_valid_two_historical_and_two_new(self):
        root, tip = fixture()
        self.assert_review(root, tip, 2, 4)

    def test_empty_pinned_genesis_with_real_batch(self):
        root, tip = fixture(old=0)
        self.assert_review(root, tip, 0, 2)

    def test_exact_max_256_ledger_entries(self):
        root, tip = fixture(old=255, added=(300,))
        self.assert_review(root, tip, 255, 256)

    def test_over_256_fails_atomically(self):
        root, tip = fixture(old=256, added=(300,))
        self.assert_hold(root, tip)

    def test_cross_batch_nonce_replay_with_new_mac_fails(self):
        root, tip = fixture()
        record = root["incoming"]["attestations"][0]
        record["nonce"] = root["before"]["entries"][0]["nonce"]
        self._resign(record)
        root["after"]["entries"][2]["nonce"] = record["nonce"]
        self.assert_hold(root, tip)

    def test_cross_batch_tip_replay_with_new_mac_fails(self):
        root, tip = fixture()
        record = root["incoming"]["attestations"][0]
        record["tip_sha256"] = root["before"]["entries"][1]["tip_sha256"]
        self._resign(record)
        root["after"]["entries"][2]["tip_sha256"] = record["tip_sha256"]
        self.assert_hold(root, tip)

    def test_untrusted_modified_historical_anchor_rejected(self):
        root, tip = fixture()
        root["before"]["entries"][0]["nonce"] = "f" * 32
        root["after"]["entries"][0]["nonce"] = "f" * 32
        self.assert_hold(root, tip)

    def test_candidate_history_rewrite_with_unchanged_anchored_before(self):
        root, tip = fixture()
        root["after"]["entries"][0]["issued_at"] = "2026-10-14T10:11:12Z"
        self.assert_hold(root, tip)

    def test_pretended_new_anchor_cannot_replace_previous_trusted_tip(self):
        root, tip = fixture()
        self.assert_hold(root, "f" * 64)
        self.assert_hold(root, "")
        self.assert_hold(root, "F" * 64)
        self.assert_hold(root, None)

    def test_noop_candidate_must_not_pass(self):
        root, tip = fixture()
        root["after"] = root["before"]
        self.assert_hold(root, tip)

    def test_truncated_candidate_must_not_pass(self):
        root, tip = fixture()
        root["after"]["entries"] = root["after"]["entries"][:1]
        self.assert_hold(root, tip)

    def test_candidate_omits_one_signed_incoming_receipt(self):
        root, tip = fixture()
        root["after"]["entries"].pop()
        self.assert_hold(root, tip)

    def test_candidate_appends_unsigned_extra_receipt(self):
        root, tip = fixture()
        root["after"]["entries"].append(entry(99, NOW))
        self.assert_hold(root, tip)

    def test_candidate_reorders_signed_receipts(self):
        root, tip = fixture()
        root["after"]["entries"][2:] = list(reversed(root["after"]["entries"][2:]))
        self.assert_hold(root, tip)

    def test_change_signing_key_id_rejected(self):
        root, tip = fixture()
        root["after"]["key_id"] = "other-key"
        self.assert_hold(root, tip)
        root, tip = fixture()
        self.assert_hold(root, tip, key_id="not-trusted")

    def test_wrong_mac_and_wrong_secret_rejected(self):
        root, tip = fixture()
        self.assert_hold(root, tip, secret=OTHER)
        root["incoming"]["attestations"][0]["mac_sha256"] = "f" * 64
        self.assert_hold(root, tip)

    def test_expired_incoming_receipt_denied(self):
        root, tip = fixture()
        self.assert_hold(root, tip, now=NOW + timedelta(days=2))

    def test_extra_grant_flags_hold_at_all_envelope_levels(self):
        for location in ("root", "before", "after", "incoming", "receipt", "entry"):
            with self.subTest(location=location):
                root, tip = fixture()
                if location == "root":
                    root["authorization_granted"] = True
                elif location == "receipt":
                    root["incoming"]["attestations"][0]["authorization_granted"] = True
                elif location == "entry":
                    root["after"]["entries"][-1]["release_approved"] = True
                else:
                    root[location]["consent_verified"] = True
                self.assert_hold(root, tip)

    def test_noncanonical_types_and_malformed_entries(self):
        for key, bad in (
            ("nonce", "G" * 32),
            ("tip_sha256", True),
            ("issued_at", "2026-10-17T16:30:00+00:00"),
        ):
            with self.subTest(key=key):
                root, tip = fixture()
                root["after"]["entries"][-1][key] = bad
                self.assert_hold(root, tip)
        root, tip = fixture()
        root["after"]["entries"][-1]["seq"] = 1
        self.assert_hold(root, tip)

    def test_duplicate_keys_invalid_json_and_nonfinite_rejected(self):
        root, tip = fixture()
        raw = encode(root)
        self.assert_hold(raw.replace(b'"schema":', b'"schema":"x","schema":', 1), tip)
        self.assert_hold(raw.replace(b'"schema":', b'"x":NaN,"schema":', 1), tip)
        self.assert_hold(raw + b"\xff", tip)
        self.assert_hold(b"", tip)
        self.assert_hold(b"[]", tip)

    def test_input_bound_and_bad_now(self):
        root, tip = fixture()
        self.assert_hold(encode(root) + b" " * MAX_UPDATE_BYTES, tip)
        self.assert_hold(root, tip, now=NOW.replace(tzinfo=None))
        self.assert_hold(root, tip, secret=b"short")

    def test_forged_previous_ledger_replay_duplicate_denied(self):
        root, _ = fixture()
        root["before"]["entries"][1]["nonce"] = root["before"]["entries"][0]["nonce"]
        # Even when an untrusted actor can calculate a new hash.
        forged_tip = self._unvalidated_hash(root["before"])
        self.assert_hold(root, forged_tip)

    @staticmethod
    def _resign(receipt):
        body = {key: value for key, value in receipt.items() if key != "mac_sha256"}
        receipt["mac_sha256"] = compute_mac(body, KEY)

    @staticmethod
    def _unvalidated_hash(value):
        import hashlib
        from lightup.scope_audit_anchor_replay_update_offline import DOMAIN
        return hashlib.sha256(DOMAIN + encode(value)).hexdigest()

    def _cli(self, raw, key=KEY, synthetic=True):
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        before, tip = fixture(now=datetime.now(timezone.utc))
        # Caller always creates matching tip from its input snapshot;
        # tests for invalid input still require one explicit anchor.
        if type(raw) is dict:
            try:
                tip = compute_ledger_anchor(raw["before"])
            except (KeyError, ValueError, TypeError):
                pass
        reader, writer = os.pipe()
        try:
            os.write(writer, key)
            os.close(writer)
            writer = -1
            cmd = [
                sys.executable, "-m",
                "lightup.scope_audit_anchor_replay_update_offline",
                "--expected-key-id", KEY_ID,
                "--expected-ledger-tip", tip,
                "--key-fd", str(reader),
            ]
            if synthetic:
                cmd.append("--synthetic-only")
            return subprocess.run(
                cmd, input=encode(raw) if type(raw) is dict else raw,
                capture_output=True, cwd=root, env=env,
                pass_fds=(reader,), timeout=10,
            )
        finally:
            os.close(reader)
            if writer >= 0:
                os.close(writer)

    def test_real_cli_review_only_exit_3_with_inherited_key_fd(self):
        root, tip = fixture(now=datetime.now(timezone.utc))
        process = self._cli(root)
        self.assertEqual(3, process.returncode, process.stderr.decode())
        self.assertEqual("REVIEW_ONLY", json.loads(process.stdout)["status"])
        self.assertNotIn(KEY, process.stdout)
        self.assertNotIn(KEY_ID.encode(), process.stdout)
        self.assertNotIn(tip.encode(), process.stdout)

    def test_real_cli_bad_mac_is_hold_and_does_not_echo(self):
        root, _ = fixture(now=datetime.now(timezone.utc))
        root["incoming"]["attestations"][0]["mac_sha256"] = "f" * 64
        process = self._cli(root)
        self.assertEqual(2, process.returncode)
        self.assertEqual("HOLD", json.loads(process.stdout)["status"])
        self.assertNotIn(b"f" * 64, process.stdout)

    def test_real_cli_without_synthetic_flag_holds(self):
        root, _ = fixture(now=datetime.now(timezone.utc))
        process = self._cli(root, synthetic=False)
        self.assertEqual(2, process.returncode)
        self.assertEqual("HOLD", json.loads(process.stdout)["status"])


if __name__ == "__main__":
    unittest.main()
