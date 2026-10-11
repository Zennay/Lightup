"""Real synthetic WSGI/SQLite acceptance of W26 opt-in CSV cookie privacy.

Never uses actual session tokens as finding text, targets external systems,
tests a live app, or certifies arbitrary sensitive-data redaction.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import test_finding_export_checked_wsi_optin_20261011_w11 as w11
from lightup.models import Severity
from lightup.webapp.finding_exports_unicode_checked import (
    create_app_with_checked_exports,
)
from lightup.webapp.finding_exports_cookie_privacy_optin_w26 import (
    CookiePrivacyCheckedFindingExportWebApp,
    create_app_with_checked_cookie_privacy,
)

CANARY = "W26SyntheticNotARealSessionValue12345"


class CsvSessionCookiePrivacyW26(unittest.TestCase):
    request = w11.CheckedFindingExportWsgiTests.request
    tearDown = w11.CheckedFindingExportWsgiTests.tearDown
    snapshot = w11.CheckedFindingExportWsgiTests.snapshot

    def setUp(self):
        w11.CheckedFindingExportWsgiTests.setUp(self)
        self.app = create_app_with_checked_cookie_privacy(self.store)

    def _replace(self, column: str, value: str):
        self.assertIn(column, ("title", "remediation"))
        with self.store._connect() as con:
            con.execute(
                f"UPDATE findings SET {column}=? WHERE finding_id=?",
                (value, self.fa.finding_id),
            )

    def test_factory_explicit_and_default_checked_factory_unchanged(self):
        self.assertIsInstance(self.app, CookiePrivacyCheckedFindingExportWebApp)
        self.assertNotIsInstance(
            create_app_with_checked_exports(self.store),
            CookiePrivacyCheckedFindingExportWebApp,
        )

    def test_clean_session_authorized_csv_remains_redacted_and_read_only(self):
        before = self.snapshot()
        status, headers, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "text/csv; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn(self.fa.finding_id, body)
        self.assertIn("password=[REDACTED]", body)
        self.assertNotIn("canary-secret", body)
        self.assertEqual(self.snapshot(), before)

    def test_cookie_in_title_or_remediation_denies_entire_csv_without_mutation(self):
        for column in ("title", "remediation"):
            with self.subTest(column=column):
                self._replace(column, "Set-Cookie: lightup_session=" + CANARY + "; Path=/")
                before = self.snapshot()
                status, headers, body = self.request(
                    "GET", self.own_url, token=self.a_token
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertNotIn("text/csv", headers["Content-Type"])
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertNotIn(self.fa.finding_id, body)
                self.assertNotIn(CANARY, body)
                self.assertEqual(self.snapshot(), before)
                self._replace(column, "synthetic ordinary text")

    def test_unicode_compatibility_cookie_label_denies(self):
        # Inspect NFKC only, reject the entire CSV; do not rewrite source.
        self._replace(
            "remediation",
            "Note: ｌｉｇｈｔｕｐ＿ｓｅｓｓｉｏｎ＝" + CANARY,
        )
        before = self.snapshot()
        status, headers, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn("text/csv", headers["Content-Type"])
        self.assertNotIn(CANARY, body)
        self.assertEqual(self.snapshot(), before)

    def test_quoted_cookie_value_also_denies_entire_csv(self):
        # Valid cookie header presentation may quote the cookie value.
        # The CSV writer doubles those quotes in the resulting cell.
        for quote in ('"', "'"):
            with self.subTest(quote=quote):
                self._replace(
                    "remediation",
                    "Set-Cookie: lightup_session=" + quote + CANARY + quote,
                )
                before = self.snapshot()
                status, headers, body = self.request(
                    "GET", self.own_url, token=self.a_token
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertNotIn(CANARY, body)
                self.assertNotIn(self.fa.finding_id, body)
                self.assertEqual(before, self.snapshot())
                self._replace("remediation", "synthetic ordinary text")

    def test_failure_in_later_row_never_releases_first_row(self):
        self.store.record_finding(
            self.operator, self.a_eng.engagement_id,
            "Second finding", Severity.MEDIUM, "synthetic.invalid",
            "synthetic impact",
            "lightup_session=" + CANARY,
            ("evidence-synthetic",),
        )
        before = self.snapshot()
        status, headers, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn("text/csv", headers["Content-Type"])
        self.assertNotIn(self.fa.finding_id, body)
        self.assertNotIn(CANARY, body)
        self.assertEqual(self.snapshot(), before)

    def test_unauthorized_tenant_still_denied_before_selection(self):
        with patch.object(self.store, "list_findings") as read:
            status, headers, body = self.request(
                "GET", self.other_url, token=self.a_token
            )
        self.assertEqual(status, "403 Forbidden")
        read.assert_not_called()
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn(self.fb.finding_id, body)

    def test_unmodified_w23_factory_control_still_exposes_synthetic_cookie(self):
        # Controlled demonstration of presentation seam; NOT a real secret.
        self._replace("title", "Set-Cookie: lightup_session=" + CANARY)
        self.app = create_app_with_checked_exports(self.store)
        status, _, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertIn(CANARY, body)
        self.app = create_app_with_checked_cookie_privacy(self.store)
        status, _, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(CANARY, body)


if __name__ == "__main__":
    unittest.main()
