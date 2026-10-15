"""Real subprocess (python -m) acceptance of #737 no-authority offline CLI.

Only locally constructed fictional stdin; no real customer/target data.
Tests actual documented process entry point, exit status and privacy output.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = "scripts.scope_737_revocation_review_cli"


def fixture(at=None, actor=None, reason=None):
    return {"revoked_at": at, "revoked_by": actor, "revocation_reason": reason}


def envelope(records):
    return json.dumps({"schema_version": 1, "records": records}).encode("utf-8")


def run_cli(raw):
    return subprocess.run(
        [sys.executable, "-m", MODULE],
        input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=ROOT, check=False, timeout=12,
    )


def assert_hold(test, process, exit_code):
    test.assertEqual(process.returncode, exit_code)
    test.assertEqual(process.stderr, b"")
    test.assertEqual(process.stdout.count(b"\n"), 1)
    data = json.loads(process.stdout)
    test.assertEqual(data["schema_version"], 1)
    test.assertEqual(data["decision"], "HOLD")
    for action in ("can_authorize", "can_dispatch", "can_release"):
        test.assertIs(data[action], False)
    return data


class RevocationRealCliSubprocessTests(unittest.TestCase):
    def test_canonical_clean_record_remains_non_authorizing(self):
        data = assert_hold(self, run_cli(envelope([fixture()])), 0)
        self.assertEqual(data["class_counts"][-1]["count"], 1)

    def test_canonical_revoked_record_remains_non_authorizing(self):
        data = assert_hold(self, run_cli(envelope([
            fixture("2026-10-15T10:00:00Z", "fictional-reviewer", "fixture-revoked")
        ])), 0)
        self.assertEqual(data["class_counts"][1]["count"], 1)

    def test_stale_revocation_provenance_is_counted_inconsistent(self):
        data = assert_hold(self, run_cli(envelope([
            fixture(None, "fictional-reviewer", "fixture-revoked")
        ])), 0)
        self.assertEqual(data["class_counts"][0]["count"], 1)

    def test_mixed_review_is_count_only_and_private(self):
        raw = envelope([
            fixture(),
            fixture("2026-10-15T10:00:00Z", "synthetic-private-reviewer", "synthetic-secret-reason"),
            fixture(None, "synthetic-private-reviewer", "synthetic-secret-reason"),
        ])
        process = run_cli(raw)
        data = assert_hold(self, process, 0)
        self.assertEqual([x["count"] for x in data["class_counts"]], [1, 1, 1])
        self.assertNotIn(b"synthetic-private-reviewer", process.stdout)
        self.assertNotIn(b"synthetic-secret-reason", process.stdout)
        self.assertNotIn("records", data)

    def test_actual_process_rejects_json_duplicate_key(self):
        raw = (b'{"schema_version":1,"records":['
               b'{"revoked_at":null,"revoked_at":null,'
               b'"revoked_by":null,"revocation_reason":null}]}')
        data = assert_hold(self, run_cli(raw), 2)
        self.assertEqual(data["reason_codes"], ["invalid_json"])
        self.assertEqual(data["class_counts"], [])

    def test_actual_process_rejects_malformed_input_without_echo(self):
        private = b"fictional-sensitive-operator-do-not-print"
        process = run_cli(b"not-JSON-" + private)
        data = assert_hold(self, process, 2)
        self.assertEqual(data["reason_codes"], ["invalid_json"])
        self.assertNotIn(private, process.stdout)

    def test_actual_process_rejects_oversize_input(self):
        data = assert_hold(self, run_cli(b"X" * 65537), 2)
        self.assertEqual(data["reason_codes"], ["input_too_large"])

    def test_actual_process_accepts_max_64_only_for_review(self):
        data = assert_hold(self, run_cli(envelope([fixture()] * 64)), 0)
        self.assertEqual(data["class_counts"][-1]["count"], 64)

    def test_actual_process_rejects_65_rows_without_partial_results(self):
        data = assert_hold(self, run_cli(envelope([fixture()] * 65)), 2)
        self.assertEqual(data["reason_codes"], ["invalid_record_count"])
        self.assertEqual(data["class_counts"], [])

    def test_real_process_denies_hidden_unicode_control_without_leak(self):
        private = "fictional\\u202esecret"
        proc = run_cli(envelope([
            fixture("2026-10-15T10:00:00Z", private, "fixture")
        ]))
        data = assert_hold(self, proc, 0)
        self.assertEqual(data["class_counts"][0]["count"], 1)
        self.assertNotIn(private.encode("utf-8"), proc.stdout)

    def test_actual_process_noncanonical_time_never_mints_authority(self):
        data = assert_hold(self, run_cli(envelope([
            fixture("2026-10-15T10:00:00+00:00", "fictional", "fixture")
        ])), 0)
        self.assertEqual(data["class_counts"][0]["count"], 1)


if __name__ == "__main__":
    unittest.main()
