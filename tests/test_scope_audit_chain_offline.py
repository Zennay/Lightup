"""Offline, synthetic-only scope audit hash-chain contract (#1556)."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from lightup.scope_audit_chain_offline import (
    MAX_BYTES,
    SCHEMA,
    ZERO_HASH,
    compute_event_hash,
    verify_chain,
)


def packet(kinds=("REVIEW_OPENED", "REVIEW_NOTE"), scope="a" * 64):
    previous = ZERO_HASH
    events = []
    for index, kind in enumerate(kinds):
        at = (datetime(2026, 10, 17, 12, 0, 0) + timedelta(seconds=index))
        body = {
            "seq": index, "kind": kind,
            "at": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scope_sha256": scope, "previous_sha256": previous,
        }
        digest = compute_event_hash(body)
        events.append({**body, "sha256": digest})
        previous = digest
    raw = json.dumps({"schema": SCHEMA, "events": events}, sort_keys=True).encode()
    return raw, previous


class ScopeAuditChainTests(unittest.TestCase):
    def assert_hold(self, raw, tip):
        receipt = verify_chain(raw, tip)
        self.assertEqual("HOLD", receipt["status"])
        self.assertEqual(0, receipt["records"])
        self.assertIs(receipt["consent_verified"], False)
        self.assertIs(receipt["authorization_granted"], False)
        self.assertIs(receipt["release_approved"], False)
        self.assertEqual("CHAIN_INVALID", receipt["reason"])

    def test_one_event_is_review_only_not_go(self):
        raw, tip = packet(("REVIEW_OPENED",))
        result = verify_chain(raw, tip)
        self.assertEqual("REVIEW_ONLY", result["status"])
        self.assertEqual(1, result["records"])
        self.assertEqual("FICTIONAL_CHAIN_ONLY", result["reason"])
        self.assertFalse(any(
            result[key] for key in ("consent_verified", "authorization_granted", "release_approved")
        ))

    def test_full_stream_and_withdrawal_is_review_only(self):
        raw, tip = packet(("REVIEW_OPENED", "REVIEW_NOTE", "REVIEW_WITHDRAWN"))
        self.assertEqual(3, verify_chain(raw, tip)["records"])

    def test_missing_tip_holds(self):
        raw, _ = packet()
        self.assert_hold(raw, "")
        self.assert_hold(raw, "A" * 64)
        self.assert_hold(raw, "0" * 64)

    def test_removed_tail_holds_even_if_remaining_links_valid(self):
        raw, tip = packet()
        doc = json.loads(raw)
        doc["events"].pop()
        self.assert_hold(json.dumps(doc).encode(), tip)

    def test_reordering_replay_and_sequence_forgery_hold(self):
        raw, tip = packet(("REVIEW_OPENED", "REVIEW_NOTE", "REVIEW_NOTE"))
        obj = json.loads(raw)
        obj["events"][1], obj["events"][2] = obj["events"][2], obj["events"][1]
        self.assert_hold(json.dumps(obj).encode(), tip)
        obj = json.loads(raw)
        obj["events"].append(dict(obj["events"][-1]))
        self.assert_hold(json.dumps(obj).encode(), tip)
        obj = json.loads(raw)
        obj["events"][1]["seq"] = True
        self.assert_hold(json.dumps(obj).encode(), tip)

    def test_content_edit_and_previous_link_edit_hold(self):
        raw, tip = packet()
        obj = json.loads(raw)
        obj["events"][1]["at"] = "2026-10-17T12:00:05Z"
        self.assert_hold(json.dumps(obj).encode(), tip)
        obj = json.loads(raw)
        obj["events"][1]["previous_sha256"] = "f" * 64
        self.assert_hold(json.dumps(obj).encode(), tip)

    def test_early_withdrawal_and_second_open_rejected(self):
        raw, tip = packet(("REVIEW_OPENED", "REVIEW_WITHDRAWN", "REVIEW_NOTE"))
        self.assert_hold(raw, tip)
        raw, tip = packet(("REVIEW_OPENED", "REVIEW_OPENED"))
        self.assert_hold(raw, tip)
        raw, tip = packet(("REVIEW_NOTE",))
        self.assert_hold(raw, tip)

    def test_unknown_event_and_forged_authority_fields_hold(self):
        raw, tip = packet()
        obj = json.loads(raw)
        obj["events"][1]["kind"] = "AUTHORIZATION_GRANTED"
        self.assert_hold(json.dumps(obj).encode(), tip)
        obj = json.loads(raw)
        obj["events"][0]["consent_verified"] = True
        self.assert_hold(json.dumps(obj).encode(), tip)
        obj = json.loads(raw)
        obj["release_approved"] = True
        self.assert_hold(json.dumps(obj).encode(), tip)

    def test_scope_digest_change_holds_even_with_rehashed_event(self):
        raw, tip = packet()
        obj = json.loads(raw)
        body = {key: value for key, value in obj["events"][1].items() if key != "sha256"}
        body["scope_sha256"] = "b" * 64
        obj["events"][1] = {**body, "sha256": compute_event_hash(body)}
        self.assert_hold(json.dumps(obj).encode(), obj["events"][1]["sha256"])
        self.assert_hold(json.dumps(obj).encode(), tip)

    def test_nonmonotonic_time_holds_even_if_rehashed(self):
        raw, _ = packet()
        obj = json.loads(raw)
        body = {key: value for key, value in obj["events"][1].items() if key != "sha256"}
        body["at"] = obj["events"][0]["at"]
        obj["events"][1] = {**body, "sha256": compute_event_hash(body)}
        self.assert_hold(json.dumps(obj).encode(), obj["events"][1]["sha256"])

    def test_strict_utc_time_shapes(self):
        for timestamp in ("2026-10-17T12:00:00+00:00", "2026-02-30T12:00:00Z",
                          "2026-10-17T12:00:00z", "2026-10-17T12:00:0Z", None):
            with self.subTest(timestamp=timestamp):
                raw, _ = packet()
                obj = json.loads(raw)
                obj["events"][0]["at"] = timestamp
                self.assert_hold(json.dumps(obj).encode(), obj["events"][-1]["sha256"])

    def test_duplicate_keys_nonfinite_and_invalid_utf8_hold(self):
        raw, tip = packet()
        self.assert_hold(raw.replace(b'"events":', b'"events":[],"events":', 1), tip)
        self.assert_hold(raw.replace(b'"seq": 0', b'"seq": NaN', 1), tip)
        self.assert_hold(raw + b"\xff", tip)

    def test_strict_schema_and_types(self):
        raw, tip = packet()
        for field, bad in (("schema", "LEGACY"), ("events", {}),
                           ("events", []), ("events", [True])):
            with self.subTest(field=field, bad=bad):
                obj = json.loads(raw)
                obj[field] = bad
                self.assert_hold(json.dumps(obj).encode(), tip)
        self.assert_hold(b"{}", tip)

    def test_boundaries_and_invalid_api_inputs(self):
        raw, tip = packet()
        self.assert_hold(raw + b" " * MAX_BYTES, tip)
        self.assert_hold(b"", tip)
        self.assert_hold("not bytes", tip)
        self.assert_hold(raw, None)
        self.assert_hold(raw, True)
        raw, tip = packet(("REVIEW_OPENED",) + ("REVIEW_NOTE",) * 64)
        self.assert_hold(raw, tip)

    def test_extra_hidden_duplicate_and_wrong_id_types(self):
        raw, tip = packet()
        obj = json.loads(raw)
        obj["events"][0]["scope_sha256"] = "Ａ" + "a" * 63
        self.assert_hold(json.dumps(obj).encode(), tip)
        obj = json.loads(raw)
        obj["events"][0]["seq"] = 0.0
        self.assert_hold(json.dumps(obj).encode(), tip)

    def _cli(self, raw, tip, *args):
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        return subprocess.run(
            [sys.executable, "-m", "lightup.scope_audit_chain_offline",
             "--expected-tip", tip, *args],
            input=raw, capture_output=True, cwd=root, env=env, timeout=10,
        )

    def test_real_cli_review_only_exit_3_and_privacy(self):
        raw, tip = packet()
        p = self._cli(raw, tip, "--synthetic-only")
        self.assertEqual(3, p.returncode, p.stderr.decode())
        receipt = json.loads(p.stdout)
        self.assertEqual("REVIEW_ONLY", receipt["status"])
        self.assertNotIn("scope_sha256", p.stdout.decode())
        self.assertNotIn("a" * 64, p.stdout.decode())

    def test_real_cli_requires_explicit_synthetic_flag(self):
        raw, tip = packet()
        p = self._cli(raw, tip)
        self.assertEqual(2, p.returncode)
        self.assertEqual("HOLD", json.loads(p.stdout)["status"])

    def test_real_cli_tampering_holds_without_echo(self):
        raw, tip = packet()
        modified = raw.replace(b"REVIEW_NOTE", b"APPROVED_NOW")
        p = self._cli(modified, tip, "--synthetic-only")
        self.assertEqual(2, p.returncode)
        self.assertEqual("HOLD", json.loads(p.stdout)["status"])
        self.assertNotIn("APPROVED_NOW", p.stdout.decode())


if __name__ == "__main__":
    unittest.main()
