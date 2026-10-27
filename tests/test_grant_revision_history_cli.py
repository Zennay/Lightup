"""Real offline CLI coverage for synthetic historical grant narrowing."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "review_grant_revision_offline.py"
_SPEC = importlib.util.spec_from_file_location("historical_grant_review_cli", _SCRIPT)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
_FIXTURE = _ROOT / "lab" / "fixtures" / "grant_revision_history_narrowing_synthetic.json"


class GrantRevisionHistoryCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.snapshot = Path(self.directory.name) / "history.json"
        self.packet = json.loads(_FIXTURE.read_text(encoding="utf-8"))

    def evaluate(self, packet=None):
        self.snapshot.write_text(json.dumps(
            self.packet if packet is None else packet), encoding="utf-8")
        return _MODULE.review_local_file(str(self.snapshot))

    def assert_non_authorizing(self, result):
        for field in ("authorization_verified", "permit_issued", "execution_enabled",
                      "merge_approved", "release_approved"):
            self.assertIs(result[field], False)

    def test_checked_in_synthetic_history_is_review_not_permission(self):
        receipt = _MODULE.review_local_file(str(_FIXTURE))
        self.assertEqual(receipt["verdict"], "REVIEW_ONLY")
        self.assertEqual(receipt["version_count"], 3)
        self.assertEqual(receipt["reviewed_transitions"], 2)
        self.assertEqual(receipt["reviewed_count"], 1)
        self.assertEqual(receipt["narrowed_count"], 4)
        self.assert_non_authorizing(receipt)

    def test_cli_never_exits_with_success_even_on_valid_history(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = _MODULE.main([str(_FIXTURE)])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 3)
        self.assertEqual(result["verdict"], "REVIEW_ONLY")
        self.assert_non_authorizing(result)

    def test_temporary_asset_widening_then_revert_is_denied(self):
        payload = deepcopy(self.packet)
        payload["history"][1]["scope"]["assets"].append("extra.example.test")
        receipt = self.evaluate(payload)
        self.assertEqual(receipt["verdict"], "HOLD")
        self.assertEqual(receipt["reason_code"], "transition_held")
        self.assertEqual(receipt["reviewed_count"], 0)
        self.assertEqual(receipt["reviewed_transitions"], 0)
        self.assert_non_authorizing(receipt)

    def test_hidden_widening_even_if_last_is_narrower_than_first(self):
        payload = deepcopy(self.packet)
        payload["history"][1]["scope"]["allowed_capabilities"] = ["headers"]
        payload["history"][2]["scope"]["allowed_capabilities"] = ["headers", "tls"]
        # The final capability set is still a subset of the original, but
        # reintroduces TLS after an intermediate version removed it.
        receipt = self.evaluate(payload)
        self.assertEqual(receipt["verdict"], "HOLD")
        self.assertEqual(receipt["reviewed_count"], 0)
        self.assert_non_authorizing(receipt)

    def test_transient_tenant_reassignment_denied_without_leak(self):
        payload = deepcopy(self.packet)
        payload["history"][1]["client_id"] = "private-client-identifier"
        receipt = self.evaluate(payload)
        self.assertEqual(receipt["verdict"], "HOLD")
        self.assertNotIn("private-client-identifier", repr(receipt))
        self.assert_non_authorizing(receipt)

    def test_duplicate_historical_snapshot_is_denied(self):
        payload = deepcopy(self.packet)
        payload["history"][1] = deepcopy(payload["history"][0])
        self.assertEqual(self.evaluate(payload)["reason_code"], "duplicate_or_noop_version")

    def test_history_cannot_contain_authority_flags(self):
        payload = deepcopy(self.packet)
        payload["history"][1]["execution_enabled"] = True
        receipt = self.evaluate(payload)
        self.assertEqual(receipt["reason_code"], "invalid_offline_snapshot")
        self.assert_non_authorizing(receipt)

    def test_history_shape_rejects_empty_single_and_nine_versions(self):
        for length in (0, 1, 9):
            with self.subTest(length=length):
                payload = {"history": [deepcopy(self.packet["history"][0]) for _ in range(length)]}
                self.assertEqual(self.evaluate(payload)["verdict"], "HOLD")

    def test_history_and_revision_batch_mixed_envelope_denied(self):
        payload = deepcopy(self.packet)
        payload["revisions"] = []
        self.assertEqual(self.evaluate(payload)["reason_code"], "invalid_offline_snapshot")

    def test_naive_unicode_time_and_bool_risk_fail_closed(self):
        for edit in ("naive_time", "bool_risk", "unicode_asset"):
            payload = deepcopy(self.packet)
            if edit == "naive_time":
                payload["history"][1]["valid_until"] = "2026-11-30T00:00:00"
            elif edit == "bool_risk":
                payload["history"][1]["scope"]["max_risk"] = True
            else:
                payload["history"][1]["scope"]["assets"].append("éxample.test")
            with self.subTest(edit=edit):
                receipt = self.evaluate(payload)
                self.assertEqual(receipt["verdict"], "HOLD")
                self.assert_non_authorizing(receipt)

    def test_duplicate_json_keys_denied_even_in_second_version(self):
        raw = json.dumps(self.packet)
        raw = raw.replace('"reference": "offline-history-only",',
                          '"reference": "offline-history-only", "reference": "fake",', 1)
        self.snapshot.write_text(raw, encoding="utf-8")
        self.assertEqual(_MODULE.review_local_file(str(self.snapshot))["verdict"], "HOLD")

    def test_no_network_database_or_target_interaction(self):
        self.snapshot.write_text(json.dumps(self.packet), encoding="utf-8")
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("sqlite3.connect", side_effect=AssertionError("database forbidden")):
            receipt = _MODULE.review_local_file(str(self.snapshot))
        self.assertEqual(receipt["verdict"], "REVIEW_ONLY")
        self.assert_non_authorizing(receipt)

    def test_shipped_atomic_two_tenant_histories_dossier_is_read_only(self):
        file = (
            _ROOT / "lab" / "fixtures"
            / "grant_revision_histories_batch_synthetic.json"
        )
        receipt = _MODULE.review_local_file(str(file))
        self.assertEqual(receipt["verdict"], "REVIEW_ONLY")
        self.assertEqual(receipt["reviewed_count"], 2)
        self.assertEqual(receipt["reviewed_transitions"], 2)
        self.assertEqual(receipt["narrowed_count"], 2)
        self.assert_non_authorizing(receipt)
        result = io.StringIO()
        with redirect_stdout(result):
            code = _MODULE.main([str(file)])
        self.assertEqual(code, 3)
        self.assert_non_authorizing(json.loads(result.getvalue()))

    def test_multi_history_late_conflict_denies_whole_packet(self):
        packet = json.loads(
            (_ROOT / "lab" / "fixtures" /
             "grant_revision_histories_batch_synthetic.json").read_text(encoding="utf-8")
        )
        for version in packet["histories"][1]:
            version["scope"]["assets"] = ["one.example.test"]
        result = self.evaluate(packet)
        self.assertEqual(result["verdict"], "HOLD")
        self.assertEqual(result["reason_code"], "cross_history_coherence_held")
        self.assertEqual(result["reviewed_count"], 0)
        self.assertEqual(result["reviewed_transitions"], 0)
        self.assert_non_authorizing(result)

    def test_multi_history_cross_tenant_cidr_defers_to_network_lane(self):
        packet = json.loads(
            (_ROOT / "lab" / "fixtures" /
             "grant_revision_histories_batch_synthetic.json").read_text(encoding="utf-8")
        )
        for version in packet["histories"][0]:
            version["scope"]["assets"] = ["192.168.0.0/24"]
        for version in packet["histories"][1]:
            version["scope"]["assets"] = ["192.168.0.42"]
        receipt = self.evaluate(packet)
        self.assertEqual(receipt["verdict"], "HOLD")
        self.assertEqual(receipt["reason_code"], "cross_history_coherence_held")
        self.assert_non_authorizing(receipt)

    def test_malformed_multihistory_denies_without_partial_counts(self):
        packet = json.loads(
            (_ROOT / "lab" / "fixtures" /
             "grant_revision_histories_batch_synthetic.json").read_text(encoding="utf-8")
        )
        for malformed in (
            {"histories": []},
            {"histories": [packet["histories"][0]] * 17},
            {"histories": [packet["histories"][0], []]},
            {"histories": [packet["histories"][0], packet["histories"][1]],
             "permit_issued": True},
        ):
            with self.subTest(rows=repr(list(malformed))):
                result = self.evaluate(malformed)
                self.assertEqual(result["verdict"], "HOLD")
                self.assertEqual(result["reviewed_count"], 0)
                self.assert_non_authorizing(result)

    def test_fifo_and_symlink_refused_in_history_mode(self):
        self.snapshot.write_text(json.dumps(self.packet), encoding="utf-8")
        symlink = Path(self.directory.name) / "linked-history.json"
        symlink.symlink_to(self.snapshot)
        self.assertEqual(_MODULE.review_local_file(str(symlink))["verdict"], "HOLD")
        if hasattr(os, "mkfifo"):
            fifo = Path(self.directory.name) / "pipe-history.json"
            os.mkfifo(fifo)
            self.assertEqual(_MODULE.review_local_file(str(fifo))["verdict"], "HOLD")


if __name__ == "__main__":
    unittest.main()
