"""Independent post-render denial tests for the optional checked CSV WSGI route.

All state is disposable SQLite; no installed ingress, customer, target, network,
authorization grant, active scan or production route is touched.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3
import unittest
from unittest.mock import patch

import test_webapp as base
from lightup.models import Severity
from lightup.webapp.finding_exports_unicode_checked import create_app_with_checked_exports


class CheckedCsvPostrenderDenialTests(unittest.TestCase):
    request = base.WebAppTest.request
    tearDown = base.WebAppTest.tearDown

    def setUp(self):
        base.WebAppTest.setUp(self)
        self.app = create_app_with_checked_exports(self.store)
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Synthetic local only"
        )
        self.finding = self.store.record_finding(
            self.operator, engagement.engagement_id,
            "Synthetic finding", Severity.LOW, "no-target.invalid",
            "Synthetic impact", "synthetic remediation", ("synthetic-evidence",),
        )
        self.url = f"/portal/{self.client_a.client_id}/findings.csv"

    def _assert_denied_without_csv(self, result):
        status, headers, body = result
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("text/csv", headers.get("Content-Type", ""))
        self.assertNotIn("Content-Disposition", headers)
        self.assertNotIn(self.finding.finding_id, body)
        self.assertNotIn("synthetic remediation", body)

    def test_session_expires_while_checked_csv_is_rendered(self):
        from lightup.finding_export_tenant_checked import render_tenant_findings_csv_checked
        before = self.store.get_finding(self.operator, self.finding.finding_id)

        def expire_after_render(*args, **kwargs):
            csv_text = render_tenant_findings_csv_checked(*args, **kwargs)
            self.assertIn(self.finding.finding_id, csv_text)
            with self.store._connect() as con:
                con.execute(
                    "UPDATE sessions SET expires_at=? WHERE token_hash=?",
                    ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                     self.store._token_hash(self.a_token)),
                )
            return csv_text

        with patch(
            "lightup.webapp.finding_exports_unicode_checked.render_tenant_findings_csv_checked",
            side_effect=expire_after_render,
        ):
            self._assert_denied_without_csv(
                self.request("GET", self.url, token=self.a_token)
            )
        self.assertEqual(before, self.store.get_finding(self.operator, self.finding.finding_id))

    def test_session_database_failure_after_render_fails_closed(self):
        real_session_context = self.store.session_context
        calls = 0

        def fail_second_lookup(token):
            nonlocal calls
            calls += 1
            if calls >= 2:
                raise sqlite3.DatabaseError("synthetic post-render database failure")
            return real_session_context(token)

        with patch.object(self.store, "session_context", side_effect=fail_second_lookup):
            self._assert_denied_without_csv(
                self.request("GET", self.url, token=self.a_token)
            )
        self.assertGreaterEqual(calls, 2)

    def test_postrender_session_lookup_none_fails_closed(self):
        real_session_context = self.store.session_context
        calls = 0

        def vanish_after_render(token):
            nonlocal calls
            calls += 1
            if calls >= 2:
                return None
            return real_session_context(token)

        with patch.object(self.store, "session_context", side_effect=vanish_after_render):
            self._assert_denied_without_csv(
                self.request("GET", self.url, token=self.a_token)
            )
        self.assertGreaterEqual(calls, 2)


if __name__ == "__main__":
    unittest.main()
