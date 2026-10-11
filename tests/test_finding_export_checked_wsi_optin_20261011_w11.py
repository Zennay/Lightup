"""Actual WSGI + durable-session acceptance of the opt-in guarded tenant CSV.

Synthetic local SQLite only; never invoke a target, production account,
installed ingress, model, grant, remediation or retest.
"""
from __future__ import annotations

import csv
import io
import unittest
from unittest.mock import patch

import test_webapp as base
from lightup.models import Severity
from lightup.webapp.finding_exports import create_app_with_exports
from lightup.webapp.finding_exports_unicode_checked import (
    CheckedFindingExportWebApp,
    create_app_with_checked_exports,
)
from lightup.webapp.security import WebSecurity


class CheckedFindingExportWsgiTests(unittest.TestCase):
    request = base.WebAppTest.request
    tearDown = base.WebAppTest.tearDown

    def setUp(self):
        base.WebAppTest.setUp(self)
        self.app = create_app_with_checked_exports(self.store)
        self.a_eng = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Local engagement A"
        )
        self.b_eng = self.store.create_engagement(
            self.operator, self.client_b.client_id, "Foreign engagement B"
        )
        self.fa = self.store.record_finding(
            self.operator, self.a_eng.engagement_id, "=Lab title", Severity.HIGH,
            "very-private-target.invalid", "private-impact",
            "password=canary-secret", ("local-evidence-canary",),
        )
        self.fb = self.store.record_finding(
            self.operator, self.b_eng.engagement_id, "Foreign tenant private finding",
            Severity.MEDIUM, "foreign-target.invalid", "other-impact",
            "foreign remediation", ("foreign-evidence",),
        )
        self.own_url = f"/portal/{self.client_a.client_id}/findings.csv"
        self.other_url = f"/portal/{self.client_b.client_id}/findings.csv"

    def snapshot(self):
        with self.store._connect() as con:
            return tuple(tuple(row) for row in con.execute(
                "SELECT finding_id,client_id,engagement_id,title,asset,remediation,"
                "retest_status,evidence_ids_json FROM findings ORDER BY finding_id"
            ))

    def test_factory_is_explicitly_separate_from_existing_default(self):
        self.assertIsInstance(self.app, CheckedFindingExportWebApp)
        self.assertNotIsInstance(create_app_with_exports(self.store), CheckedFindingExportWebApp)
        self.assertEqual(
            type(self.app).__module__,
            "lightup.webapp.finding_exports_unicode_checked",
        )
        self.assertEqual(len([item for item in self.app.routes
                              if item[1].pattern.endswith("findings[.]csv$")]), 2)

    def test_real_signed_in_client_get_returns_checked_redacted_csv(self):
        before = self.snapshot()
        status, headers, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "text/csv; charset=utf-8")
        self.assertEqual(
            headers["Content-Disposition"], 'attachment; filename="LightUp-findings.csv"'
        )
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(int(headers["Content-Length"]), len(body.encode("utf-8")))
        rows = list(csv.DictReader(io.StringIO(body)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["finding_id"], self.fa.finding_id)
        self.assertEqual(rows[0]["title"], "'=Lab title")
        self.assertEqual(rows[0]["remediation"], "password=[REDACTED]")
        for forbidden in (
            "canary-secret", "local-evidence-canary", "very-private-target.invalid",
            "private-impact", "Foreign tenant private finding",
        ):
            self.assertNotIn(forbidden, body)
        self.assertEqual(before, self.snapshot())

    def test_anonymous_and_revoked_sessions_prevent_serialize_or_read(self):
        for token, expect in ((None, "303 See Other"), ("bad-cookie", "303 See Other")):
            with self.subTest(token=token), patch.object(self.store, "list_findings") as read:
                status, _, body = self.request("GET", self.own_url, token=token)
                self.assertEqual(status, expect)
                self.assertNotIn(self.fa.finding_id, body)
                read.assert_not_called()
        self.store.revoke_session(self.a_token)
        with patch.object(self.store, "list_findings") as read:
            status, _, body = self.request("GET", self.own_url, token=self.a_token)
            self.assertEqual(status, "303 See Other")
            read.assert_not_called()
            self.assertNotIn(self.fa.finding_id, body)

    def test_foreign_client_denied_before_data_access(self):
        with patch.object(self.store, "list_findings") as read:
            status, _, body = self.request("GET", self.other_url, token=self.a_token)
            self.assertEqual(status, "403 Forbidden")
            read.assert_not_called()
            self.assertNotIn(self.fb.finding_id, body)

    def test_operator_must_choose_exact_tenant_and_engagement(self):
        status, _, body = self.request("GET", self.own_url, token=self.op_token)
        self.assertEqual(status, "200 OK")
        self.assertIn(self.fa.finding_id, body)
        self.assertNotIn(self.fb.finding_id, body)
        match = f"/portal/{self.client_a.client_id}/engagements/{self.a_eng.engagement_id}/findings.csv"
        status, _, body = self.request("GET", match, token=self.op_token)
        self.assertEqual(status, "200 OK")
        self.assertIn(self.fa.finding_id, body)
        mismatch = f"/portal/{self.client_a.client_id}/engagements/{self.b_eng.engagement_id}/findings.csv"
        with patch.object(self.store, "list_findings") as read:
            status, _, body = self.request("GET", mismatch, token=self.op_token)
            self.assertEqual(status, "403 Forbidden")
            read.assert_not_called()
            self.assertNotIn(self.fb.finding_id, body)

    def test_invalid_mark_formula_later_row_fails_entire_wsi_export_with_no_mutation(self):
        self.store.record_finding(
            self.operator, self.a_eng.engagement_id,
            "Second synthetic finding", Severity.LOW,
            "private-target.invalid", "private impact",
            "\u0301 \ufe0f =SUM(1)", ("private evidence",),
        )
        before = self.snapshot()
        with patch(
            "lightup.finding_export_unicode_integrity.render_findings_csv"
        ) as writer:
            status, headers, body = self.request("GET", self.own_url, token=self.a_token)
            self.assertEqual(status, "400 Bad Request")
            writer.assert_not_called()
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn(self.fa.finding_id, body)
        self.assertNotIn("SUM(1)", body)
        self.assertEqual(before, self.snapshot())

    def test_unicode_compatibility_formula_in_hidden_target_fails_before_csv(self):
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET asset=? WHERE finding_id=?",
                ("\ufe0f\uff1dSUM(1)", self.fa.finding_id),
            )
        with patch(
            "lightup.finding_export_unicode_integrity.render_findings_csv"
        ) as writer:
            status, _, body = self.request("GET", self.own_url, token=self.a_token)
            self.assertEqual(status, "400 Bad Request")
            writer.assert_not_called()
            self.assertNotIn(self.fa.finding_id, body)

    def test_existing_legacy_factory_remains_unprotected_for_control(self):
        with self.store._connect() as con:
            con.execute(
                "UPDATE findings SET title=? WHERE finding_id=?",
                ("\u0301=SUM(1)", self.fa.finding_id),
            )
        self.app = create_app_with_exports(self.store)
        status, _, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertIn("\u0301=SUM(1)", body)
        self.app = create_app_with_checked_exports(self.store)
        status, _, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(self.fa.finding_id, body)

    def test_unrecognized_get_and_post_do_not_create_a_write_path(self):
        status, _, body = self.request("GET", self.own_url.replace(".csv", "_csv"), token=self.a_token)
        self.assertEqual(status, "404 Not Found")
        self.assertNotIn(self.fa.finding_id, body)
        before = self.snapshot()
        status, _, body = self.request("POST", self.own_url, token=self.a_token, csrf=self.a_csrf)
        self.assertEqual(status, "404 Not Found")
        self.assertNotIn(self.fa.finding_id, body)
        self.assertEqual(before, self.snapshot())

    def test_production_origin_guard_precedes_session_resolution(self):
        self.app = create_app_with_checked_exports(
            self.store, WebSecurity(public_origin="https://lightup.test")
        )
        environ = {
            "REQUEST_METHOD": "GET", "PATH_INFO": self.own_url,
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_HOST": "hostile.invalid",
            "HTTP_COOKIE": f"lightup_session={self.a_token}",
            "wsgi.input": io.BytesIO(),
        }
        recorded = {}
        with patch.object(self.store, "session_context") as session:
            payload = b"".join(
                self.app(environ, lambda status, headers: recorded.update(
                    status=status, headers=dict(headers)
                ))
            )
            session.assert_not_called()
        self.assertEqual(recorded["status"], "403 Forbidden")
        self.assertIn("Strict-Transport-Security", recorded["headers"])
        self.assertNotIn(self.fa.finding_id.encode(), payload)

    def test_portal_contains_same_nonauthorizing_download_link(self):
        status, _, html = self.request(
            "GET", f"/portal/{self.client_a.client_id}", token=self.a_token
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(html.count(f'href="{self.own_url}"'), 1)


    def test_live_login_then_logout_observes_authenticated_route(self):
        status, headers, _ = self.request(
            "POST", "/login",
            {"email": "a@acme.test", "password": "client-a-password"},
        )
        self.assertEqual(status, "303 See Other")
        fresh_cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", fresh_cookie)
        self.assertIn("SameSite=Strict", fresh_cookie)
        token = fresh_cookie.split("lightup_session=")[1].split(";")[0]
        status, _, body = self.request("GET", self.own_url, token=token)
        self.assertEqual(status, "200 OK")
        self.assertIn(self.fa.finding_id, body)
        _, resolved = self.store.session_context(token)
        status, _, _ = self.request("POST", "/logout", token=token, csrf=resolved)
        self.assertEqual(status, "303 See Other")
        with patch.object(self.store, "list_findings") as read:
            status, _, body = self.request("GET", self.own_url, token=token)
            self.assertEqual(status, "303 See Other")
            read.assert_not_called()
            self.assertNotIn(self.fa.finding_id, body)

    def test_current_db_client_membership_overrides_stale_session_identity(self):
        # Synthetic operator-side transfer: existing session token MUST resolve
        # current role/tenant at each new request, not an old in-memory context.
        status, _, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertIn(self.fa.finding_id, body)
        with self.store._connect() as con:
            con.execute(
                "UPDATE users SET client_id=? WHERE user_id=?",
                (self.client_b.client_id, self.user_a.user_id),
            )
        with patch.object(self.store, "list_findings") as read:
            status, _, body = self.request("GET", self.own_url, token=self.a_token)
            self.assertEqual(status, "403 Forbidden")
            read.assert_not_called()
            self.assertNotIn(self.fa.finding_id, body)
        status, _, body = self.request("GET", self.other_url, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertIn(self.fb.finding_id, body)
        self.assertNotIn(self.fa.finding_id, body)

    def test_expired_session_never_reaches_checked_producer(self):
        from datetime import datetime, timedelta, timezone

        with self.store._connect() as con:
            con.execute(
                "UPDATE sessions SET expires_at=? WHERE token_hash=?",
                ((datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
                 self.store._token_hash(self.a_token)),
            )
        with patch.object(self.store, "list_findings") as read:
            status, _, body = self.request("GET", self.own_url, token=self.a_token)
            self.assertEqual(status, "303 See Other")
            read.assert_not_called()
            self.assertNotIn(self.fa.finding_id, body)


    def test_session_revoked_during_checked_render_never_releases_csv(self):
        from lightup.finding_export_tenant_checked import render_tenant_findings_csv_checked

        before = self.snapshot()
        def render_then_revoke(*args, **kwargs):
            output = render_tenant_findings_csv_checked(*args, **kwargs)
            self.assertIn(self.fa.finding_id, output)
            self.store.revoke_session(self.a_token)
            return output

        with patch(
            "lightup.webapp.finding_exports_unicode_checked.render_tenant_findings_csv_checked",
            side_effect=render_then_revoke,
        ):
            status, headers, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn(self.fa.finding_id, body)
        self.assertNotIn("canary-secret", body)
        self.assertEqual(before, self.snapshot())

    def test_account_transferred_mid_render_cannot_receive_old_tenant_csv(self):
        from lightup.finding_export_tenant_checked import render_tenant_findings_csv_checked

        def render_then_change_membership(*args, **kwargs):
            output = render_tenant_findings_csv_checked(*args, **kwargs)
            self.assertIn(self.fa.finding_id, output)
            with self.store._connect() as con:
                con.execute(
                    "UPDATE users SET client_id=? WHERE user_id=?",
                    (self.client_b.client_id, self.user_a.user_id),
                )
            return output

        with patch(
            "lightup.webapp.finding_exports_unicode_checked.render_tenant_findings_csv_checked",
            side_effect=render_then_change_membership,
        ):
            status, _, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "403 Forbidden")
        self.assertNotIn(self.fa.finding_id, body)
        # Future requests now use the new persisted account tenant scope.
        status, _, body = self.request("GET", self.other_url, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertIn(self.fb.finding_id, body)
        self.assertNotIn(self.fa.finding_id, body)

    def test_direct_handler_cannot_claim_session_from_context_alone(self):
        from lightup.webapp.app import AuthState

        with patch.object(self.store, "list_findings") as read:
            response = self.app.download_findings(
                AuthState(self.operator, None),
                {},
                self.client_a.client_id,
            )
            self.assertEqual(response.status, "403 Forbidden")
            read.assert_not_called()
            self.assertNotIn(self.fa.finding_id.encode(), response.body)


if __name__ == "__main__":
    unittest.main()
