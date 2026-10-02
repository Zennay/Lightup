from __future__ import annotations

import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role, RoleError
from lightup.labrun import FIXTURE_EXPECTED, run_lab_baseline
from lightup.labsync import ensure_lab_engagement, persist_lab_findings, retest_finding
from lightup.models import RetestStatus


class MutableHandler(BaseHTTPRequestHandler):
    """Fixture whose hardening can be toggled, to exercise retest semantics."""

    hardened = False

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if type(self).hardened:
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class LabSyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MutableHandler)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        MutableHandler.hardened = False
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.store = DomainStore(base / "domain.db")
        self.state_db = base / "state.db"
        self.operator = AccessContext("op-1", Role.OPERATOR)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ensure_lab_engagement_is_idempotent_and_operator_only(self):
        one = ensure_lab_engagement(self.store, self.operator)
        two = ensure_lab_engagement(self.store, self.operator)
        self.assertEqual(one.engagement_id, two.engagement_id)
        client_ctx = AccessContext("u", Role.CLIENT_ADMIN, one.client_id)
        with self.assertRaises(RoleError):
            ensure_lab_engagement(self.store, client_ctx)

    def test_findings_persist_and_are_tenant_visible(self):
        engagement = ensure_lab_engagement(self.store, self.operator)
        result = run_lab_baseline(self.url, self.state_db, expected=FIXTURE_EXPECTED)
        records = persist_lab_findings(self.store, self.operator,
                                       engagement.engagement_id, result)
        self.assertGreaterEqual(len(records), 3)
        stored = self.store.list_findings(self.operator,
                                          engagement_id=engagement.engagement_id)
        self.assertEqual(len(stored), len(records))
        self.assertIn(result["evidence_id"], stored[0].evidence_ids)
        lab_ctx = AccessContext("lab-user", Role.CLIENT_ADMIN, engagement.client_id)
        self.assertEqual(len(self.store.list_findings(lab_ctx)), len(records))

    def test_retest_semantics_fixed_pending_regression(self):
        engagement = ensure_lab_engagement(self.store, self.operator)
        result = run_lab_baseline(self.url, self.state_db)
        records = persist_lab_findings(self.store, self.operator,
                                       engagement.engagement_id, result)
        csp = next(r for r in records if "Content-Security-Policy" in r.title)

        # Fix not applied yet: retest keeps it pending.
        pending = retest_finding(self.store, self.operator, csp)
        self.assertIs(pending.retest_status, RetestStatus.FIX_PENDING)

        # Fix applied: retest confirms.
        MutableHandler.hardened = True
        fixed = retest_finding(self.store, self.operator, pending)
        self.assertIs(fixed.retest_status, RetestStatus.FIXED)

        # Fix rolled back after a FIXED verdict: regression.
        MutableHandler.hardened = False
        regressed = retest_finding(self.store, self.operator, fixed)
        self.assertIs(regressed.retest_status, RetestStatus.REGRESSION)

    def test_retest_is_lab_only_and_known_checks_only(self):
        engagement = ensure_lab_engagement(self.store, self.operator)
        result = run_lab_baseline(self.url, self.state_db)
        records = persist_lab_findings(self.store, self.operator,
                                       engagement.engagement_id, result)
        finding = records[0]
        # A finding pointing at a public asset fails closed on retest.
        import dataclasses

        from lightup.labeval import LabIsolationError
        forged = dataclasses.replace(finding, asset="http://example.com/")
        with self.assertRaises(LabIsolationError):
            retest_finding(self.store, self.operator, forged)
        # Unknown titles cannot be auto-retested.
        unknown = dataclasses.replace(finding, title="Manually written finding")
        with self.assertRaises(ValueError):
            retest_finding(self.store, self.operator, unknown)


if __name__ == "__main__":
    unittest.main()
