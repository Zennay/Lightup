"""Synthetic read-only offline batch acceptance; no target contact."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("scope_review_batch", SCRIPTS / "check_scope_review_batch_offline.py")
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)


def item(tenant="tenant_001", asset="asset_001", request="req_001"):
    return {"schema_version": 1, "request_id": request, "tenant_id": tenant,
            "asset_id": asset, "requester_id": "user_001", "authorization_reference": "AUTH-001",
            "scope_reference": "SCOPE-001", "requested_mode": "TARGET_ACTIVE", "risk_level": 3,
            "requested_capabilities": ["http_headers", "tls_baseline"],
            "review_evidence_digests": ["a" * 64],
            "window_start": "2026-10-20T11:00:00Z", "window_end": "2026-10-20T12:00:00Z"}


def receipt(rows):
    return batch.evaluate(json.dumps(rows, ensure_ascii=False).encode())


class OfflineBatchTests(unittest.TestCase):
    def assertSafe(self, r, state="HOLD", reason=None):
        self.assertEqual(state, r["state"])
        if reason:
            self.assertEqual(reason, r["reason"])
        self.assertTrue(r["non_authorizing"])
        self.assertTrue(all(r[k] is False for k in batch.single.AUTHORITY_FLAGS))
        if state == "HOLD":
            self.assertEqual(r["packets_checked"], 0)
        self.assertEqual(set(r), {"state", "reason", "packets_checked", "non_authorizing",
                                  *batch.single.AUTHORITY_FLAGS})

    def test_one_valid_shape_still_no_permission(self):
        r = receipt([item()])
        self.assertSafe(r, "REVIEW_ONLY", "SHAPE_ONLY_UNVERIFIED")
        self.assertEqual(r["packets_checked"], 1)

    def test_empty_batch_denied(self):
        self.assertSafe(receipt([]), reason="BATCH_SHAPE")

    def test_nonlist_denied(self):
        for rows in ({}, None, "hello", True, 1):
            with self.subTest(rows=rows):
                self.assertSafe(receipt(rows), reason="BATCH_SHAPE")

    def test_33_rows_denied(self):
        rows = [item(request=f"req_{i:03d}", asset=f"asset_{i:03d}") for i in range(33)]
        self.assertSafe(receipt(rows), reason="BATCH_SHAPE")

    def test_full_32_rows_reviewer_only(self):
        rows = [item(request=f"req_{i:03d}", asset=f"asset_{i:03d}") for i in range(32)]
        result = receipt(rows)
        self.assertSafe(result, "REVIEW_ONLY")
        self.assertEqual(result["packets_checked"], 32)

    def test_duplicate_request_ids_within_same_tenant_denied(self):
        rows = [item(), item(asset="asset_002")]
        self.assertSafe(receipt(rows), reason="DUPLICATE_REQUEST")

    def test_duplicate_request_ids_across_tenants_denied(self):
        rows = [item(), item(tenant="tenant_002")]
        self.assertSafe(receipt(rows), reason="DUPLICATE_REQUEST")

    def test_unsorted_rows_denied(self):
        self.assertSafe(receipt([item(asset="asset_002", request="req_002"), item()]),
                        reason="BATCH_ORDER")

    def test_cross_tenant_reference_denied(self):
        rows = [item(), item(tenant="tenant_002", request="req_002")]
        rows[1]["review_evidence_digests"] = ["b" * 64]
        self.assertSafe(receipt(rows), reason="CROSS_TENANT_REFERENCE")

    def test_cross_tenant_scope_reference_denied(self):
        rows = [item(), item(tenant="tenant_002", request="req_002")]
        rows[1].update(authorization_reference="AUTH-002", review_evidence_digests=["b" * 64])
        self.assertSafe(receipt(rows), reason="CROSS_TENANT_REFERENCE")

    def test_cross_tenant_evidence_denied(self):
        rows = [item(), item(tenant="tenant_002", request="req_002")]
        rows[1].update(authorization_reference="AUTH-002", scope_reference="SCOPE-002")
        self.assertSafe(receipt(rows), reason="CROSS_TENANT_EVIDENCE")

    def test_two_tenants_with_distinct_references_accepted_as_shape_only(self):
        rows = [item(), item(tenant="tenant_002", request="req_002")]
        rows[1].update(authorization_reference="AUTH-002", scope_reference="SCOPE-002",
                       review_evidence_digests=["b" * 64])
        self.assertSafe(receipt(rows), "REVIEW_ONLY")

    def test_same_asset_overlapping_shared_capability_denied(self):
        rows = [item(), item(request="req_002")]
        rows[1].update(window_start="2026-10-20T11:30:00Z",
                       window_end="2026-10-20T12:30:00Z")
        self.assertSafe(receipt(rows), reason="OVERLAPPING_ASSET_CAPABILITY")

    def test_same_asset_equal_window_denied(self):
        self.assertSafe(receipt([item(), item(request="req_002")]),
                        reason="OVERLAPPING_ASSET_CAPABILITY")

    def test_same_asset_adjacent_windows_accepted(self):
        rows = [item(), item(request="req_002")]
        rows[1].update(window_start="2026-10-20T12:00:00Z",
                       window_end="2026-10-20T13:00:00Z")
        self.assertSafe(receipt(rows), "REVIEW_ONLY")

    def test_same_asset_disjoint_capabilities_accepted(self):
        rows = [item(), item(request="req_002")]
        rows[1].update(requested_capabilities=["service_inventory"])
        self.assertSafe(receipt(rows), "REVIEW_ONLY")

    def test_same_tenant_different_asset_overlapping_accepted(self):
        rows = [item(), item(asset="asset_002", request="req_002")]
        self.assertSafe(receipt(rows), "REVIEW_ONLY")

    def test_invalid_last_of_32_holds_atomically(self):
        rows = [item(request=f"req_{i:03d}", asset=f"asset_{i:03d}") for i in range(32)]
        rows[-1]["risk_level"] = True
        self.assertSafe(receipt(rows), reason="ITEM_MODE_RISK")

    def test_extra_fake_grant_field_denied(self):
        rows = [item()]
        rows[0]["authorization_verified"] = True
        self.assertSafe(receipt(rows), reason="ITEM_SCHEMA_FIELDS")

    def test_duplicate_json_keys_denied(self):
        self.assertSafe(batch.evaluate(b'[{"schema_version":1,"schema_version":0}]'),
                        reason="DUPLICATE_KEY")

    def test_nested_nonfinite_denied(self):
        self.assertSafe(batch.evaluate(b'[{"x":NaN}]'), reason="NONFINITE_NUMBER")

    def test_nonbytes_denied(self):
        for raw in ([], None, "[]", bytearray(b"[]")):
            self.assertSafe(batch.evaluate(raw), reason="SIZE_LIMIT")

    def test_oversize_bytes_denied(self):
        self.assertSafe(batch.evaluate(b" " * (batch.MAX_BATCH_BYTES + 1)),
                        reason="SIZE_LIMIT")

    def test_local_cli_valid_returns_reviewonly(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "batch.json"
            path.write_text(json.dumps([item()]))
            proc = subprocess.run([sys.executable, str(SCRIPTS / "check_scope_review_batch_offline.py"),
                                   str(path)], text=True, capture_output=True, timeout=5)
            self.assertEqual(proc.returncode, 0)
            self.assertSafe(json.loads(proc.stdout), "REVIEW_ONLY")
            self.assertFalse(proc.stderr)

    def test_local_cli_oversize_file_denied(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "big.json"
            path.write_bytes(b"x" * (batch.MAX_BATCH_BYTES + 1))
            proc = subprocess.run([sys.executable, str(SCRIPTS / "check_scope_review_batch_offline.py"),
                                   str(path)], text=True, capture_output=True, timeout=5)
            self.assertEqual(proc.returncode, 2)
            self.assertSafe(json.loads(proc.stdout), reason="SIZE_LIMIT")

    def test_symlink_denied_without_path_echo(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "packet.json"
            path.write_text(json.dumps([item()]))
            link = Path(d) / "SECRET.json"
            link.symlink_to(path)
            proc = subprocess.run([sys.executable, str(SCRIPTS / "check_scope_review_batch_offline.py"),
                                   str(link)], text=True, capture_output=True, timeout=5)
            self.assertEqual(proc.returncode, 2)
            self.assertSafe(json.loads(proc.stdout), reason="INPUT_UNAVAILABLE")
            self.assertNotIn("SECRET", proc.stdout + proc.stderr)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX")
    def test_fifo_denied_without_block(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "pipe.json"
            os.mkfifo(path)
            proc = subprocess.run([sys.executable, str(SCRIPTS / "check_scope_review_batch_offline.py"),
                                   str(path)], text=True, capture_output=True, timeout=5)
            self.assertEqual(proc.returncode, 2)
            self.assertSafe(json.loads(proc.stdout), reason="NOT_REGULAR_FILE")

    def test_script_contains_no_network_or_runtime_imports(self):
        src = (SCRIPTS / "check_scope_review_batch_offline.py").read_text()
        for name in ("import socket", "import requests", "urllib.request", "subprocess",
                     "ToolExecutor", "AuthorizationGrant"):
            self.assertNotIn(name, src)


if __name__ == "__main__":
    unittest.main()
