import io
import unittest
from unittest.mock import patch

import test_webapp as base
from lightup.models import Severity
from lightup.webapp.finding_exports import create_app_with_exports
from lightup.webapp.security import WebSecurity


class FindingExportWebTests(unittest.TestCase):
    request = base.WebAppTest.request
    tearDown = base.WebAppTest.tearDown

    def setUp(self):
        base.WebAppTest.setUp(self)
        self.app = create_app_with_exports(self.store)
        self.eng_a = self.store.create_engagement(self.operator, self.client_a.client_id, "Export A")
        self.eng_b = self.store.create_engagement(self.operator, self.client_b.client_id, "Export B")
        self.fa = self.store.record_finding(
            self.operator, self.eng_a.engagement_id, "=Formula finding", Severity.HIGH,
            "private-a.invalid", "Private impact", "password=canary-secret", ("evidence-a",))
        self.fb = self.store.record_finding(
            self.operator, self.eng_b.engagement_id, "Private B", Severity.LOW,
            "private-b.invalid", "Private impact", "Fix B", ("evidence-b",))
        self.url = f"/portal/{self.client_a.client_id}/findings.csv"

    def test_download_requires_live_session(self):
        status, headers, body = self.request("GET", self.url)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], "/login")
        self.assertNotIn(self.fa.finding_id, body)
        self.store.revoke_session(self.a_token)
        status, _, body = self.request("GET", self.url, token=self.a_token)
        self.assertEqual(status, "303 See Other")
        self.assertNotIn(self.fa.finding_id, body)

    def test_own_client_download_is_guarded_summary_attachment(self):
        status, headers, body = self.request("GET", self.url, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "text/csv; charset=utf-8")
        self.assertEqual(headers["Content-Disposition"], 'attachment; filename="LightUp-findings.csv"')
        self.assertIn("'=Formula finding", body)
        self.assertIn("password=[REDACTED]", body)
        for forbidden in ("private-a.invalid", "evidence-a", "canary-secret", "Private B"):
            self.assertNotIn(forbidden, body)

    def test_csv_response_preserves_security_headers(self):
        _, headers, body = self.request("GET", self.url, token=self.a_token)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(int(headers["Content-Length"]), len(body.encode("utf-8")))
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_operator_download_selects_only_named_client(self):
        status, _, body = self.request("GET", self.url, token=self.op_token)
        self.assertEqual(status, "200 OK")
        self.assertIn(self.fa.finding_id, body)
        self.assertNotIn(self.fb.finding_id, body)

    def test_foreign_client_download_denied_before_read(self):
        url = f"/portal/{self.client_b.client_id}/findings.csv"
        with patch.object(self.store, "list_findings") as read:
            status, _, body = self.request("GET", url, token=self.a_token)
            self.assertEqual(status, "403 Forbidden")
            read.assert_not_called()
        self.assertNotIn("Private B", body)

    def test_engagement_download_and_mismatch(self):
        own = f"/portal/{self.client_a.client_id}/engagements/{self.eng_a.engagement_id}/findings.csv"
        status, _, body = self.request("GET", own, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertIn(self.fa.finding_id, body)
        foreign = f"/portal/{self.client_a.client_id}/engagements/{self.eng_b.engagement_id}/findings.csv"
        status, _, body = self.request("GET", foreign, token=self.op_token)
        self.assertEqual(status, "403 Forbidden")
        self.assertNotIn(self.fb.finding_id, body)

    def test_post_download_does_not_create_write_route(self):
        status, _, body = self.request("POST", self.url, token=self.a_token, csrf=self.a_csrf)
        self.assertEqual(status, "404 Not Found")
        self.assertNotIn(self.fa.finding_id, body)

    def test_csv_extension_is_literal_and_errors_are_generic(self):
        status, _, _ = self.request("GET", self.url.replace(".csv", "Xcsv"), token=self.a_token)
        self.assertEqual(status, "404 Not Found")
        missing = "/portal/missing-client/findings.csv"
        status, _, body = self.request("GET", missing, token=self.op_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertIn("Export unavailable", body)
        self.assertNotIn("missing-client", body)

    def test_portal_has_one_download_link(self):
        _, _, body = self.request("GET", f"/portal/{self.client_a.client_id}", token=self.a_token)
        self.assertEqual(body.count(f'href="{self.url}"'), 1)
        self.assertIn("Download CSV", body)

    def test_corrupt_finding_lineage_cannot_download(self):
        with self.store._connect() as con:
            con.execute("UPDATE findings SET client_id=? WHERE finding_id=?",
                        (self.client_a.client_id, self.fb.finding_id))
        status, _, body = self.request("GET", self.url, token=self.a_token)
        self.assertEqual(status, "403 Forbidden")
        self.assertNotIn(self.fa.finding_id, body)
        self.assertNotIn(self.fb.finding_id, body)

    def test_production_host_guard_precedes_export_handler(self):
        self.app = create_app_with_exports(self.store, WebSecurity(public_origin="https://lightup.test"))
        env = {"REQUEST_METHOD": "GET", "PATH_INFO": self.url,
               "REMOTE_ADDR": "127.0.0.1", "HTTP_X_FORWARDED_PROTO": "https",
               "HTTP_HOST": "evil.test", "HTTP_COOKIE": f"lightup_session={self.a_token}",
               "wsgi.input": io.BytesIO()}
        captured = {}
        with patch.object(self.store, "session_context") as resolve:
            body = b"".join(self.app(env, lambda s, h: captured.update(status=s, headers=dict(h))))
            resolve.assert_not_called()
        self.assertEqual(captured["status"], "403 Forbidden")
        self.assertNotIn(self.fa.finding_id.encode(), body)
        self.assertIn("Strict-Transport-Security", captured["headers"])


if __name__ == "__main__":
    unittest.main()
