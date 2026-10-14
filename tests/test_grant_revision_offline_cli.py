"""Disposable synthetic JSON tests for opt-in grant revision review CLI."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_grant_revision_offline.py"
_SPEC = importlib.util.spec_from_file_location("offline_grant_review_cli", _SCRIPT)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def _grant(grant_id="g1", client_id="client1", assets=None):
    return {
        "grant_id": grant_id, "client_id": client_id, "engagement_id": "eng1",
        "approved_by": "operator1", "reference": "ref1",
        "scope": {
            "assets": list(assets or ["a.example.test", "b.example.test"]),
            "excluded_assets": [],
            "allowed_capabilities": ["headers", "tls"], "max_risk": 3,
        },
        "valid_from": "2026-10-01T00:00:00Z",
        "valid_until": "2026-10-02T00:00:00Z",
        "recurring_retest_allowed": False,
    }


def _packet():
    old = _grant()
    new = deepcopy(old)
    new["scope"]["assets"] = ["a.example.test"]
    new["scope"]["allowed_capabilities"] = ["headers"]
    new["valid_until"] = "2026-10-01T23:00:00Z"
    return {"revisions": [{"current": old, "proposed": new}]}


class OfflineGrantReviewCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "packet.json"

    def _write(self, packet):
        self.path.write_text(json.dumps(packet, ensure_ascii=False), encoding="utf-8")
        return str(self.path)

    def _review(self, packet):
        return _MODULE.review_local_file(self._write(packet))

    def assert_non_authorizing(self, receipt):
        for name in ("authorization_verified", "permit_issued", "execution_enabled",
                     "merge_approved", "release_approved"):
            self.assertIs(receipt[name], False)

    def test_shipped_synthetic_fixture_is_read_only_and_not_a_permit(self):
        fixture = (
            Path(__file__).resolve().parents[1]
            / "lab" / "fixtures" / "grant_revision_narrowing_synthetic.json"
        )
        receipt = _MODULE.review_local_file(str(fixture))
        self.assertEqual(receipt["verdict"], "REVIEW_ONLY")
        self.assertEqual(receipt["reviewed_count"], 1)
        self.assertEqual(receipt["narrowed_count"], 4)
        self.assert_non_authorizing(receipt)
        output = io.StringIO()
        with redirect_stdout(output):
            code = _MODULE.main([str(fixture)])
        self.assertEqual(code, 3)
        self.assertFalse(json.loads(output.getvalue())["execution_enabled"])

    def test_positive_syntactic_review_exits_nonzero(self):
        self._write(_packet())
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = _MODULE.main([str(self.path)])
        receipt = json.loads(output.getvalue())
        self.assertEqual(exit_code, 3)
        self.assertEqual(receipt["verdict"], "REVIEW_ONLY")
        self.assertEqual(receipt["reviewed_count"], 1)
        self.assert_non_authorizing(receipt)

    def test_untrusted_widened_asset_exits_hold(self):
        packet = _packet()
        packet["revisions"][0]["proposed"]["scope"]["assets"].append("new.example.test")
        self._write(packet)
        output = io.StringIO()
        with redirect_stdout(output):
            code = _MODULE.main([str(self.path)])
        self.assertEqual(code, 2)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["verdict"], "HOLD")
        self.assertEqual(receipt["reviewed_count"], 0)
        self.assert_non_authorizing(receipt)

    def test_nested_duplicate_key_denied(self):
        raw = json.dumps(_packet()).replace(
            '"grant_id": "g1",', '"grant_id": "g1", "grant_id": "g2",', 1)
        self.path.write_text(raw, encoding="utf-8")
        self.assertEqual(_MODULE.review_local_file(str(self.path))["verdict"], "HOLD")

    def test_spoofed_authority_field_is_not_accepted(self):
        packet = _packet()
        packet["authorization_verified"] = True
        self.assertEqual(self._review(packet)["reason_code"], "invalid_offline_snapshot")
        packet = _packet()
        packet["revisions"][0]["proposed"]["permit_issued"] = True
        self.assertEqual(self._review(packet)["verdict"], "HOLD")

    def test_refuse_bool_risk_or_integer_retest(self):
        for field, value in (("risk", True), ("retest", 1)):
            packet = _packet()
            p = packet["revisions"][0]["proposed"]
            if field == "risk":
                p["scope"]["max_risk"] = value
            else:
                p["recurring_retest_allowed"] = value
            with self.subTest(field=field):
                self.assertEqual(self._review(packet)["reason_code"], "invalid_offline_snapshot")

    def test_refuse_noncanonical_times(self):
        for window in (
            "2026-10-01T23:00:00+00:00", "2026-10-01T23:00:00.000Z",
            "2026-10-01T23:00:00", "2026-02-30T01:00:00Z",
        ):
            packet = _packet()
            packet["revisions"][0]["proposed"]["valid_until"] = window
            with self.subTest(window=window):
                self.assertEqual(self._review(packet)["verdict"], "HOLD")

    def test_cross_tenant_collision_denies_whole_batch(self):
        packet = _packet()
        new = deepcopy(packet["revisions"][0])
        for side in ("current", "proposed"):
            new[side]["client_id"] = "client2"
            new[side]["grant_id"] = "g2"
        packet["revisions"].append(new)
        receipt = self._review(packet)
        self.assertEqual(receipt["verdict"], "HOLD")
        self.assertEqual(receipt["reason_code"], "cross_tenant_asset_overlap")
        self.assertEqual(receipt["reviewed_count"], 0)

    def test_invalid_json_and_unicode_denied_without_errors(self):
        for raw in ('{bad', 'NaN', '"\ud800"', "{}", "[]"):
            with self.subTest(raw=raw):
                self.path.write_bytes(raw.encode("utf-8", "surrogatepass"))
                self.assert_non_authorizing(_MODULE.review_local_file(str(self.path)))
                self.assertEqual(_MODULE.review_local_file(str(self.path))["verdict"], "HOLD")

    def test_oversized_regular_file_and_too_many_entries_denied(self):
        self.path.write_bytes(b" " * (_MODULE.MAX_FILE_BYTES + 1))
        self.assertEqual(_MODULE.review_local_file(str(self.path))["verdict"], "HOLD")
        packet = _packet()
        packet["revisions"] *= 33
        self.assertEqual(self._review(packet)["verdict"], "HOLD")

    def test_reject_symlink_to_snapshot(self):
        self._write(_packet())
        alias = Path(self.directory.name) / "alias.json"
        alias.symlink_to(self.path)
        self.assertEqual(_MODULE.review_local_file(str(alias))["verdict"], "HOLD")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO")
    def test_reject_named_pipe_without_waiting(self):
        fifo = Path(self.directory.name) / "pipe.json"
        os.mkfifo(fifo)
        self.assertEqual(_MODULE.review_local_file(str(fifo))["verdict"], "HOLD")

    def test_no_socket_database_or_private_details_in_failure(self):
        packet = _packet()
        secret = "secret-customer-123.example.test"
        packet["revisions"][0]["proposed"]["scope"]["assets"].append(secret)
        self._write(packet)
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("sqlite3.connect", side_effect=AssertionError("database forbidden")):
            receipt = _MODULE.review_local_file(str(self.path))
        self.assertEqual(receipt["verdict"], "HOLD")
        self.assertNotIn(secret, repr(receipt))
        self.assertNotIn(str(self.path), repr(receipt))
        self.assert_non_authorizing(receipt)


if __name__ == "__main__":
    unittest.main()
