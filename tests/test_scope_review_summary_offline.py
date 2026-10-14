"""W6: safe aggregate-only analysis of synthetic multi-client review metadata."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_scope_review_batch_offline as batch


def request(i, mode="TARGET_ACTIVE", risk=3, capabilities=None):
    if capabilities is None:
        capabilities = ["http_headers"]
    return {
        "schema_version": 1, "request_id": f"req_{i:03d}",
        "tenant_id": "tenant_001", "asset_id": f"asset_{i:03d}",
        "requester_id": "user_001", "authorization_reference": "AUTH-001",
        "scope_reference": "SCOPE-001", "requested_mode": mode, "risk_level": risk,
        "requested_capabilities": capabilities, "review_evidence_digests": ["a" * 64],
        "window_start": "2026-10-20T11:00:00Z",
        "window_end": "2026-10-20T12:00:00Z",
    }


def review(rows, **flags):
    return batch.evaluate(json.dumps(rows).encode(), **flags)


class OfflineRiskHistogramTests(unittest.TestCase):
    def assertNoAuthority(self, receipt):
        self.assertTrue(receipt["non_authorizing"])
        for key in batch.single.AUTHORITY_FLAGS:
            self.assertIs(receipt[key], False)

    def assertZeroOnHold(self, receipt):
        self.assertEqual("HOLD", receipt["state"])
        self.assertEqual(0, receipt["packets_checked"])
        self.assertEqual({m: 0 for m in sorted(batch.single.MODES)}, receipt["mode_counts"])
        self.assertEqual({str(i): 0 for i in range(6)}, receipt["risk_counts"])
        self.assertNoAuthority(receipt)

    def test_happy_summary_covers_all_modes_without_identifiers(self):
        rows = [
            request(1, "ANALYSIS_ONLY", 0, ["future_simulation"]),
            request(2, "PASSIVE_PUBLIC", 1, ["future_simulation"]),
            request(3, "LAB_ACTIVE", 3, ["tls_baseline"]),
            request(4, "TARGET_ACTIVE", 4, ["http_headers"]),
        ]
        receipt = review(rows, include_summary=True)
        self.assertEqual("REVIEW_ONLY", receipt["state"])
        self.assertEqual(4, receipt["packets_checked"])
        self.assertEqual({"ANALYSIS_ONLY": 1, "LAB_ACTIVE": 1,
                          "PASSIVE_PUBLIC": 1, "TARGET_ACTIVE": 1}, receipt["mode_counts"])
        self.assertEqual({"0": 1, "1": 1, "2": 0, "3": 1, "4": 1, "5": 0},
                         receipt["risk_counts"])
        self.assertNotIn("asset_001", json.dumps(receipt))
        self.assertNotIn("tenant_001", json.dumps(receipt))
        self.assertNotIn("AUTH-001", json.dumps(receipt))
        self.assertNoAuthority(receipt)

    def test_default_receipt_keeps_original_fields(self):
        receipt = review([request(1)])
        self.assertNotIn("mode_counts", receipt)
        self.assertNotIn("risk_counts", receipt)
        self.assertEqual("REVIEW_ONLY", receipt["state"])
        self.assertNoAuthority(receipt)

    def test_single_packet_summary_exact_totals(self):
        r = review([request(1)], include_summary=True)
        self.assertEqual(sum(r["mode_counts"].values()), 1)
        self.assertEqual(sum(r["risk_counts"].values()), 1)
        self.assertNoAuthority(r)

    def test_invalid_last_packet_zeroes_entire_summary(self):
        rows = [request(i) for i in range(1, 33)]
        rows[-1]["risk_level"] = True
        r = review(rows, include_summary=True)
        self.assertEqual("ITEM_MODE_RISK", r["reason"])
        self.assertZeroOnHold(r)

    def test_same_asset_overlap_zeroes_entire_summary(self):
        rows = [request(1), request(2)]
        rows[1]["asset_id"] = "asset_001"
        r = review(rows, include_summary=True)
        self.assertEqual("OVERLAPPING_ASSET_CAPABILITY", r["reason"])
        self.assertZeroOnHold(r)

    def test_duplicate_request_zeroes_entire_summary(self):
        rows = [request(1), request(2)]
        rows[1]["request_id"] = "req_001"
        r = review(rows, include_summary=True)
        self.assertEqual("BATCH_ORDER", r["reason"])
        self.assertZeroOnHold(r)

    def test_nonfinite_json_zero_summary(self):
        r = batch.evaluate(b'[{"risk_level":NaN}]', include_summary=True)
        self.assertEqual("NONFINITE_NUMBER", r["reason"])
        self.assertZeroOnHold(r)

    def test_invalid_policy_fails_closed_without_summary(self):
        for value in ("true", 1, None, [], {"yes": True}):
            with self.subTest(value=value):
                r = review([request(1)], include_summary=value)
                self.assertEqual("HOLD", r["state"])
                self.assertEqual("INVALID_SUMMARY_POLICY", r["reason"])
                self.assertNotIn("mode_counts", r)
                self.assertNotIn("risk_counts", r)
                self.assertNoAuthority(r)

    def test_private_policy_cli_file_hold_zero_counts(self):
        if not hasattr(os, "geteuid"):
            self.skipTest("requires POSIX")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "batch.json"
            path.write_text(json.dumps([request(1)]))
            path.chmod(0o644)
            run = subprocess.run([sys.executable, str(SCRIPTS / "check_scope_review_batch_offline.py"),
                                  "--require-private-file", "--summary", str(path)],
                                 capture_output=True, text=True, timeout=5)
            self.assertEqual(2, run.returncode)
            r = json.loads(run.stdout)
            self.assertEqual("PRIVATE_FILE_REQUIRED", r["reason"])
            self.assertZeroOnHold(r)
            self.assertFalse(run.stderr)

    def test_summary_cli_review_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "batch.json"
            path.write_text(json.dumps([request(1)]))
            run = subprocess.run([sys.executable, str(SCRIPTS / "check_scope_review_batch_offline.py"),
                                  "--summary", str(path)],
                                 capture_output=True, text=True, timeout=5)
            self.assertEqual(0, run.returncode)
            r = json.loads(run.stdout)
            self.assertEqual("REVIEW_ONLY", r["state"])
            self.assertEqual(1, r["mode_counts"]["TARGET_ACTIVE"])
            self.assertEqual(1, r["risk_counts"]["3"])
            self.assertNoAuthority(r)
            self.assertFalse(run.stderr)

    def test_private_cli_empty_batch_zero_counts(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "empty.json"
            path.write_text("[]")
            run = subprocess.run([sys.executable, str(SCRIPTS / "check_scope_review_batch_offline.py"),
                                  "--summary", str(path)], capture_output=True,
                                 text=True, timeout=5)
            self.assertEqual(2, run.returncode)
            self.assertZeroOnHold(json.loads(run.stdout))


if __name__ == "__main__":
    unittest.main()
