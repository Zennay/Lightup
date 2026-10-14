"""Acceptance for W9 offline review-delta monotonicity, without real targets."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_scope_review_delta_offline as delta
import check_scope_review_packet_offline as single


def row(i=1):
    return {
        "schema_version": 1, "request_id": f"req_{i:03d}",
        "tenant_id": "tenant_001", "asset_id": f"asset_{i:03d}",
        "requester_id": "user_001", "authorization_reference": "AUTH-001",
        "scope_reference": "SCOPE-001", "requested_mode": "TARGET_ACTIVE",
        "risk_level": 3,
        "requested_capabilities": ["http_headers", "tls_baseline"],
        "review_evidence_digests": ["a" * 64],
        "window_start": "2026-10-20T11:00:00Z", "window_end": "2026-10-20T12:00:00Z",
    }


def compare(before, after):
    return delta.compare(json.dumps(before).encode(), json.dumps(after).encode())


class ReviewDeltaTests(unittest.TestCase):
    def assertSafe(self, result, state="HOLD", reason=None):
        self.assertEqual(result["state"], state)
        if reason is not None:
            self.assertEqual(result["reason"], reason)
        self.assertTrue(result["non_authorizing"])
        self.assertTrue(all(result[k] is False for k in single.AUTHORITY_FLAGS))
        if state == "HOLD":
            for key in ("retained_requests", "narrowed_requests", "removed_requests"):
                self.assertEqual(0, result[key], key)

    def test_unchanged_review_stays_non_authorizing(self):
        r = compare([row()], [row()])
        self.assertSafe(r, "REVIEW_ONLY", "SYNTAX_ONLY_UNVERIFIED")
        self.assertEqual((1, 0, 0), (r["retained_requests"],
                                     r["removed_requests"], r["narrowed_requests"]))

    def test_subsetting_capabilities_risk_window_and_removing_rows(self):
        original = [row(1), row(2)]
        narrowed = copy.deepcopy(original[0])
        narrowed["risk_level"] = 2
        narrowed["requested_capabilities"] = ["http_headers"]
        narrowed["window_start"] = "2026-10-20T11:15:00Z"
        narrowed["window_end"] = "2026-10-20T11:45:00Z"
        r = compare(original, [narrowed])
        self.assertSafe(r, "REVIEW_ONLY")
        self.assertEqual((1, 1, 1), (r["retained_requests"],
                                     r["removed_requests"], r["narrowed_requests"]))

    def test_one_capability_removed_only_passes(self):
        p = row()
        proposed = copy.deepcopy(p)
        proposed["requested_capabilities"] = ["http_headers"]
        self.assertSafe(compare([p], [proposed]), "REVIEW_ONLY")

    def test_only_end_narrowing_passes(self):
        p = row()
        proposed = copy.deepcopy(p)
        proposed["window_end"] = "2026-10-20T11:30:00Z"
        self.assertSafe(compare([p], [proposed]), "REVIEW_ONLY")

    def test_new_request_is_rejected_even_same_item_count(self):
        self.assertSafe(compare([row(1)], [row(2)]), reason="ADDED_REQUEST")

    def test_new_request_added_to_existing_is_rejected(self):
        self.assertSafe(compare([row(1)], [row(1), row(2)]), reason="ADDED_REQUEST")

    def test_all_requests_removed_is_invalid_per_batch_contract(self):
        self.assertSafe(compare([row(1)], []), reason="BATCH_SHAPE")

    def test_identity_changed_denied(self):
        for field, value in (
            ("tenant_id", "tenant_999"), ("asset_id", "asset_999"),
            ("requester_id", "user_999"),
        ):
            with self.subTest(field=field):
                proposed = row()
                proposed[field] = value
                self.assertSafe(compare([row()], [proposed]), reason="IDENTITY_CHANGED")

    def test_authorization_scope_or_evidence_reference_changed_denied(self):
        for field, value in (
            ("authorization_reference", "AUTH-002"),
            ("scope_reference", "SCOPE-002"),
            ("review_evidence_digests", ["b" * 64]),
        ):
            with self.subTest(field=field):
                proposed = row()
                proposed[field] = value
                self.assertSafe(compare([row()], [proposed]), reason="PROVENANCE_CHANGED")

    def test_switch_to_lab_mode_not_assumed_less_privileged(self):
        proposed = row()
        proposed["requested_mode"] = "LAB_ACTIVE"
        self.assertSafe(compare([row()], [proposed]), reason="MODE_CHANGED")

    def test_raised_risk_denied(self):
        proposed = row()
        proposed["risk_level"] = 4
        self.assertSafe(compare([row()], [proposed]), reason="RISK_WIDENED")

    def test_added_capability_denied(self):
        original = row()
        original["requested_capabilities"] = ["http_headers"]
        proposed = copy.deepcopy(original)
        proposed["requested_capabilities"] = ["http_headers", "tls_baseline"]
        self.assertSafe(compare([original], [proposed]), reason="CAPABILITY_WIDENED")

    def test_earlier_start_denied(self):
        proposed = row()
        proposed["window_start"] = "2026-10-20T10:59:00Z"
        self.assertSafe(compare([row()], [proposed]), reason="WINDOW_WIDENED")

    def test_later_end_denied(self):
        proposed = row()
        proposed["window_end"] = "2026-10-20T12:01:00Z"
        self.assertSafe(compare([row()], [proposed]), reason="WINDOW_WIDENED")

    def test_window_squeezed_below_minimum_denied(self):
        proposed = row()
        proposed["window_start"] = "2026-10-20T11:59:30Z"
        self.assertSafe(compare([row()], [proposed]), reason="ITEM_WINDOW_BOUNDS")

    def test_malformed_old_snapshot_denied(self):
        original = row()
        original["risk_level"] = True
        self.assertSafe(compare([original], [row()]), reason="ITEM_MODE_RISK")

    def test_malformed_new_snapshot_denied(self):
        proposed = row()
        proposed["review_evidence_digests"] = []
        self.assertSafe(compare([row()], [proposed]), reason="ITEM_EVIDENCE_SHAPE")

    def test_duplicate_json_keys_denied(self):
        raw = json.dumps([row()]).encode()
        tampered = raw.replace(b'"risk_level": 3', b'"risk_level": 3, "risk_level": 4')
        self.assertSafe(delta.compare(raw, tampered), reason="DUPLICATE_KEY")

    def test_giant_or_wrong_input_type_denied(self):
        valid = json.dumps([row()]).encode()
        for invalid in ("[]", None, b"x" * (delta.batch.MAX_BATCH_BYTES + 1)):
            with self.subTest(type=str(type(invalid))):
                self.assertSafe(delta.compare(valid, invalid), reason="SIZE_LIMIT")

    def test_unrelated_customer_data_absent_from_receipt(self):
        a = row()
        a["authorization_reference"] = "PRIVATE-AUTH-123"
        b = copy.deepcopy(a)
        b["authorization_reference"] = "PRIVATE-AUTH-124"
        serialized = json.dumps(compare([a], [b]))
        for secret in ("PRIVATE-AUTH", "tenant_001", "user_001", "asset_001"):
            self.assertNotIn(secret, serialized)

    def test_cli_happy_shape_not_authority(self):
        with tempfile.TemporaryDirectory() as d:
            previous = Path(d) / "prev.json"
            proposed = Path(d) / "proposal.json"
            previous.write_text(json.dumps([row(1), row(2)]))
            candidate = row(1)
            candidate["risk_level"] = 2
            proposed.write_text(json.dumps([candidate]))
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "check_scope_review_delta_offline.py"),
                 str(previous), str(proposed)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertSafe(data, "REVIEW_ONLY")
            self.assertEqual(1, data["removed_requests"])
            self.assertFalse(proc.stderr)

    def test_cli_missing_input_opaque_hold(self):
        with tempfile.TemporaryDirectory() as d:
            previous = Path(d) / "prev.json"
            previous.write_text(json.dumps([row()]))
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "check_scope_review_delta_offline.py"),
                 str(previous), str(Path(d) / "PRIVATE-CUSTOMER-SECRET.json")],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(2, proc.returncode)
            self.assertNotIn("PRIVATE-CUSTOMER-SECRET", proc.stdout + proc.stderr)
            self.assertSafe(json.loads(proc.stdout), reason="INPUT_UNAVAILABLE")

    def test_wrong_run_cannot_make_risk_true_on_hold(self):
        bad = row()
        bad["risk_level"] = True
        result = compare([row(1), row(2)], [row(1), bad])
        self.assertSafe(result, reason="BATCH_ORDER")


if __name__ == "__main__":
    unittest.main()
