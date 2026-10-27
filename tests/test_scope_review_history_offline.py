"""Offline history review rejects temporary scope widening and all false authority."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_scope_review_history_offline as history
import check_scope_review_packet_offline as single


def item(n=1):
    return {
        "schema_version": 1, "request_id": f"req_{n:03d}",
        "tenant_id": "tenant_001", "asset_id": f"asset_{n:03d}",
        "requester_id": "user_001", "authorization_reference": "AUTH-001",
        "scope_reference": "SCOPE-001", "requested_mode": "TARGET_ACTIVE",
        "risk_level": 3, "requested_capabilities": ["http_headers", "tls_baseline"],
        "review_evidence_digests": ["a" * 64],
        "window_start": "2026-10-20T11:00:00Z",
        "window_end": "2026-10-20T12:00:00Z",
    }


def check(*versions):
    return history.compare_history(tuple(json.dumps(v).encode() for v in versions))


class OfflineHistoryTests(unittest.TestCase):
    def assertSafe(self, receipt, state="HOLD", reason=None):
        self.assertEqual(state, receipt["state"])
        if reason:
            self.assertEqual(reason, receipt["reason"])
        self.assertTrue(receipt["non_authorizing"])
        for key in single.AUTHORITY_FLAGS:
            self.assertIs(receipt[key], False)
        if state == "HOLD":
            self.assertEqual(0, receipt["transitions_checked"])
            self.assertEqual(0, receipt["narrowing_events"])

    def test_two_identical_versions_review_only(self):
        r = check([item()], [item()])
        self.assertSafe(r, "REVIEW_ONLY")
        self.assertEqual((1, 0), (r["transitions_checked"], r["narrowing_events"]))

    def test_four_versions_only_narrowing_review_only(self):
        first = [item(1), item(2), item(3)]
        second = [item(1), item(2)]
        third = [item(1)]
        fourth = [item(1)]
        fourth[0]["requested_capabilities"] = ["http_headers"]
        r = check(first, second, third, fourth)
        self.assertSafe(r, "REVIEW_ONLY")
        self.assertEqual((3, 3), (r["transitions_checked"], r["narrowing_events"]))

    def test_temporary_risk_widening_cannot_hide_in_final(self):
        original = [item()]
        wider = [item()]
        wider[0]["risk_level"] = 4
        r = check(original, wider, original)
        self.assertSafe(r, reason="RISK_WIDENED")

    def test_temporary_capability_widening_cannot_hide(self):
        limited = [item()]
        limited[0]["requested_capabilities"] = ["http_headers"]
        widened = [item()]
        r = check(limited, widened, limited)
        self.assertSafe(r, reason="CAPABILITY_WIDENED")

    def test_temporary_earlier_window_cannot_hide(self):
        original = [item()]
        wider = [item()]
        wider[0]["window_start"] = "2026-10-20T10:30:00Z"
        self.assertSafe(check(original, wider, original), reason="WINDOW_WIDENED")

    def test_removed_request_cannot_be_reintroduced(self):
        original = [item(1), item(2)]
        removed = [item(1)]
        r = check(original, removed, original)
        self.assertSafe(r, reason="ADDED_REQUEST")

    def test_mode_switch_in_middle_denied(self):
        original = [item()]
        middle = [item()]
        middle[0]["requested_mode"] = "LAB_ACTIVE"
        self.assertSafe(check(original, middle, middle), reason="MODE_CHANGED")

    def test_late_provenance_replacement_denied_atomically(self):
        first = [item()]
        second = [item()]
        second[0]["risk_level"] = 2
        third = copy.deepcopy(second)
        third[0]["scope_reference"] = "SCOPE-002"
        self.assertSafe(check(first, second, third), reason="PROVENANCE_CHANGED")

    def test_malformed_middle_version_denied(self):
        middle = [item()]
        middle[0]["risk_level"] = True
        self.assertSafe(check([item()], middle, [item()]), reason="ITEM_MODE_RISK")

    def test_oldest_invalid_prevents_lookback(self):
        oldest = [item()]
        oldest[0]["requested_capabilities"] = []
        self.assertSafe(check(oldest, [item()]), reason="ITEM_CAPABILITIES")

    def test_less_than_two_or_more_than_four_versions_hold(self):
        for data in ((), (b"[]",), (b"[]",)*5, [], None):
            with self.subTest(data=str(type(data))):
                self.assertSafe(history.compare_history(data), reason="VERSION_COUNT")

    def test_wrong_type_in_versus_rejected(self):
        for bad in ([], "[]", None, True):
            r = history.compare_history((json.dumps([item()]).encode(), bad))
            self.assertSafe(r, reason="INVALID_FILE_BYTES")

    def test_overlarge_single_source_denied(self):
        a = json.dumps([item()]).encode()
        self.assertSafe(history.compare_history((a, b"x" * (history.batch.MAX_BATCH_BYTES+1))),
                        reason="SIZE_LIMIT")

    def test_no_customer_data_in_receipt(self):
        proposed = [item()]
        proposed[0]["scope_reference"] = "PRIVATE-SCOPE-123"
        r = check([item()], proposed)
        wire = json.dumps(r)
        for token in ("PRIVATE", "tenant_001", "asset_001", "SCOPE-001"):
            self.assertNotIn(token, wire)
        self.assertSafe(r, reason="PROVENANCE_CHANGED")

    def test_cli_four_private_files_review_only(self):
        with tempfile.TemporaryDirectory() as d:
            names = []
            for i in range(4):
                path = Path(d)/f"version-{i}.json"
                row = item()
                row["risk_level"] = 3 if i == 0 else 2
                path.write_text(json.dumps([row]))
                path.chmod(0o600)
                names.append(str(path))
            run = subprocess.run(
                [sys.executable, str(SCRIPTS / "check_scope_review_history_offline.py"),
                 "--require-private-file", *names],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(0, run.returncode, run.stderr)
            r = json.loads(run.stdout)
            self.assertSafe(r, "REVIEW_ONLY")
            self.assertEqual(3, r["transitions_checked"])
            self.assertEqual(1, r["narrowing_events"])

    def test_cli_missing_intermediate_does_not_leak_path(self):
        with tempfile.TemporaryDirectory() as d:
            before = Path(d)/"before.json"
            before.write_text(json.dumps([item()]))
            absent = Path(d)/"SECRET-customer-name.json"
            after = Path(d)/"after.json"
            after.write_text(json.dumps([item()]))
            run = subprocess.run(
                [sys.executable, str(SCRIPTS / "check_scope_review_history_offline.py"),
                 str(before), str(absent), str(after)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(2, run.returncode)
            self.assertNotIn("SECRET", run.stdout + run.stderr)
            self.assertSafe(json.loads(run.stdout), reason="INPUT_UNAVAILABLE")

    def test_cli_invalid_number_of_inputs_returns_hold(self):
        with tempfile.TemporaryDirectory() as d:
            one = Path(d)/"single.json"
            one.write_text(json.dumps([item()]))
            run = subprocess.run(
                [sys.executable, str(SCRIPTS / "check_scope_review_history_offline.py"),
                 str(one)], capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(2, run.returncode)
            self.assertSafe(json.loads(run.stdout), reason="VERSION_COUNT")


if __name__ == "__main__":
    unittest.main()
