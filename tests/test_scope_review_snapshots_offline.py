"""Standalone, synthetic-only multi-snapshot consistency and privacy acceptance."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_scope_review_packet_offline as single
import check_scope_review_snapshots_offline as snapshots


def row(tenant=1, asset=1, request=1, start="2026-10-20T11:00:00Z",
        end="2026-10-20T12:00:00Z", caps=None):
    return {
        "schema_version": 1, "request_id": f"req_{request:03d}",
        "tenant_id": f"tenant_{tenant:03d}", "asset_id": f"asset_{asset:03d}",
        "requester_id": "user_001",
        "authorization_reference": f"AUTH-{tenant:03d}",
        "scope_reference": f"SCOPE-{tenant:03d}",
        "requested_mode": "TARGET_ACTIVE", "risk_level": 3,
        "requested_capabilities": caps or ["http_headers"],
        "review_evidence_digests": [f"{tenant:x}" * 64],
        "window_start": start, "window_end": end,
    }


def evaluate(*file_packets, **kwargs):
    return snapshots.inspect_files(tuple(json.dumps(p).encode() for p in file_packets), **kwargs)


class CrossSnapshotTests(unittest.TestCase):
    def assertSafe(self, receipt, status=None):
        if status:
            self.assertEqual(status, receipt["state"])
        self.assertTrue(receipt["non_authorizing"])
        for key in single.AUTHORITY_FLAGS:
            self.assertIs(receipt[key], False)
        if receipt["state"] == "HOLD":
            self.assertEqual(0, receipt["files_checked"])
            self.assertEqual(0, receipt["packets_checked"])

    def test_two_individually_valid_distinct_assets_are_shape_only(self):
        result = evaluate([row(asset=1, request=1)], [row(asset=2, request=2)])
        self.assertSafe(result, "REVIEW_ONLY")
        self.assertEqual(2, result["packets_checked"])
        self.assertEqual(2, result["files_checked"])

    def test_same_asset_overlap_split_across_files_is_hold(self):
        result = evaluate([row(asset=1, request=1)], [row(asset=1, request=2)])
        self.assertEqual("OVERLAPPING_ASSET_CAPABILITY", result["reason"])
        self.assertSafe(result, "HOLD")

    def test_same_asset_adjacent_review_windows_are_not_conflict(self):
        result = evaluate([row(request=1)],
                          [row(request=2, start="2026-10-20T12:00:00Z",
                               end="2026-10-20T13:00:00Z")])
        self.assertSafe(result, "REVIEW_ONLY")

    def test_same_asset_disjoint_capabilities_are_not_conflict(self):
        result = evaluate([row(request=1)],
                          [row(request=2, caps=["tls_baseline"])])
        self.assertSafe(result, "REVIEW_ONLY")

    def test_cross_file_duplicate_request_id_denied(self):
        result = evaluate([row(asset=1)], [row(asset=2)])
        self.assertEqual("DUPLICATE_REQUEST", result["reason"])
        self.assertSafe(result, "HOLD")

    def test_cross_tenant_reference_collision_denied(self):
        other = row(tenant=2, request=2)
        other["authorization_reference"] = "AUTH-001"
        result = evaluate([row(tenant=1)], [other])
        self.assertEqual("CROSS_TENANT_REFERENCE", result["reason"])
        self.assertSafe(result, "HOLD")

    def test_cross_tenant_evidence_reuse_denied(self):
        other = row(tenant=2, request=2)
        other["review_evidence_digests"] = ["1" * 64]
        result = evaluate([row(tenant=1)], [other])
        self.assertEqual("CROSS_TENANT_EVIDENCE", result["reason"])
        self.assertSafe(result, "HOLD")

    def test_each_file_must_be_individually_valid(self):
        invalid = [row(asset=2, request=2), row(asset=1, request=1)]
        result = evaluate([row(asset=3, request=3)], invalid)
        self.assertEqual("BATCH_ORDER", result["reason"])
        self.assertSafe(result, "HOLD")

    def test_one_or_five_files_hold(self):
        for rawfiles in ((b"[]",), (b"[]",)*5, ()):
            with self.subTest(n=len(rawfiles)):
                self.assertEqual("FILE_COUNT", snapshots.inspect_files(rawfiles)["reason"])
                self.assertSafe(snapshots.inspect_files(rawfiles), "HOLD")

    def test_wrong_types_hold(self):
        for value in ([], "[]", None, (b"[]", []), (b"[]", 8)):
            with self.subTest(value=value):
                result = snapshots.inspect_files(value)
                self.assertSafe(result, "HOLD")

    def test_total_more_than_32_rows_holds(self):
        left = [row(asset=i, request=i) for i in range(1, 17)]
        right = [row(asset=i, request=i) for i in range(17, 34)]
        result = evaluate(left, right)
        self.assertEqual("TOTAL_ITEMS", result["reason"])
        self.assertSafe(result, "HOLD")

    def test_late_malformed_item_stops_entire_preview(self):
        later = row(asset=2, request=2)
        later["risk_level"] = True
        result = evaluate([row(asset=1)], [later], include_summary=True)
        self.assertTrue(all(n == 0 for n in result["mode_counts"].values()))
        self.assertTrue(all(n == 0 for n in result["risk_counts"].values()))
        self.assertSafe(result, "HOLD")

    def test_summary_shows_only_counts_not_private_values(self):
        result = evaluate([row(asset=1, request=1)], [row(asset=2, request=2)],
                          include_summary=True)
        self.assertSafe(result, "REVIEW_ONLY")
        self.assertEqual(2, result["mode_counts"]["TARGET_ACTIVE"])
        self.assertEqual(2, result["risk_counts"]["3"])
        serialized = json.dumps(result)
        for hidden in ("tenant_001", "asset_001", "req_001", "AUTH-001", "SCOPE-001"):
            self.assertNotIn(hidden, serialized)

    def test_summary_is_opt_in(self):
        result = evaluate([row(asset=1, request=1)], [row(asset=2, request=2)])
        self.assertNotIn("mode_counts", result)
        self.assertNotIn("risk_counts", result)
        self.assertSafe(result, "REVIEW_ONLY")

    def test_one_bad_snapshot_zeroes_summary(self):
        data = (json.dumps([row()]).encode(), b"[{\"x\":NaN}]")
        result = snapshots.inspect_files(data, include_summary=True)
        self.assertEqual("NONFINITE_NUMBER", result["reason"])
        self.assertEqual(0, sum(result["risk_counts"].values()))
        self.assertSafe(result, "HOLD")

    def test_cli_accepts_two_local_files_without_target_io(self):
        with tempfile.TemporaryDirectory() as d:
            files = []
            for i in (1, 2):
                path = Path(d) / f"review{i}.json"
                path.write_text(json.dumps([row(asset=i, request=i)]))
                files.append(str(path))
            process = subprocess.run(
                [sys.executable, str(SCRIPTS / "check_scope_review_snapshots_offline.py"),
                 "--summary", *files],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(0, process.returncode, process.stderr)
            data = json.loads(process.stdout)
            self.assertSafe(data, "REVIEW_ONLY")
            self.assertEqual(2, data["files_checked"])
            self.assertEqual(2, data["risk_counts"]["3"])
            self.assertFalse(process.stderr)

    def test_cli_missing_file_no_path_leak_and_zero_counts(self):
        with tempfile.TemporaryDirectory() as d:
            valid = Path(d) / "valid.json"
            valid.write_text(json.dumps([row()]))
            unknown = Path(d) / "SECRET-customer.json"
            process = subprocess.run(
                [sys.executable, str(SCRIPTS / "check_scope_review_snapshots_offline.py"),
                 "--summary", str(valid), str(unknown)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(2, process.returncode)
            self.assertNotIn("SECRET", process.stdout + process.stderr)
            data = json.loads(process.stdout)
            self.assertEqual("INPUT_UNAVAILABLE", data["reason"])
            self.assertEqual(0, sum(data["mode_counts"].values()))
            self.assertSafe(data, "HOLD")

    def test_cli_repeated_same_file_is_hold(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "packet.json"
            file.write_text(json.dumps([row()]))
            process = subprocess.run(
                [sys.executable, str(SCRIPTS / "check_scope_review_snapshots_offline.py"),
                 str(file), str(file)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(2, process.returncode)
            self.assertSafe(json.loads(process.stdout), "HOLD")


if __name__ == "__main__":
    unittest.main()
