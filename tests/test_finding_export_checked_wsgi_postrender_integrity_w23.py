"""Synthetic WSGI regression: post-render session shape is an auth boundary.

Tests a new opt-in checked CSV only. No installed ingress, real tenant,
scanner, grant, remediation, retest, or default export is exercised.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import test_finding_export_checked_wsi_optin_20261011_w11 as w11


class PostRenderSessionIntegrityTests(unittest.TestCase):
    setUp = w11.CheckedFindingExportWsgiTests.setUp
    tearDown = w11.CheckedFindingExportWsgiTests.tearDown
    request = w11.CheckedFindingExportWsgiTests.request
    snapshot = w11.CheckedFindingExportWsgiTests.snapshot

    def _request_with_postrender_session(self, second_value):
        original = self.store.session_context
        calls = []

        def session_context(token):
            calls.append(token)
            if len(calls) == 1:
                return original(token)  # genuine WSGI dispatch authentication
            return second_value

        before = self.snapshot()
        with patch.object(self.store, "session_context", side_effect=session_context):
            result = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(calls, [self.a_token, self.a_token])
        self.assertEqual(before, self.snapshot())
        return result

    def test_real_durable_postrender_session_retains_checked_download(self):
        context, csrf = self.store.session_context(self.a_token)
        status, headers, body = self._request_with_postrender_session((context, csrf))
        self.assertEqual(status, "200 OK")
        self.assertIn(self.fa.finding_id, body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("canary-secret", body)

    def test_malformed_postrender_session_shapes_deny_without_csv(self):
        context, csrf = self.store.session_context(self.a_token)
        bad = (
            (), [], {}, object(), 0, False,
            (context,), (context, None), (context, 1),
            (context, ""), (context, csrf + "-rotated"),
            [context, csrf], {"context": context, "csrf": csrf},
        )
        for item in bad:
            with self.subTest(shape=repr(item)[:80]):
                status, headers, body = self._request_with_postrender_session(item)
                self.assertEqual(status, "403 Forbidden")
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertNotIn("text/csv", headers["Content-Type"])
                self.assertNotIn(self.fa.finding_id, body)
                self.assertNotIn("canary-secret", body)


    def test_persisted_csrf_rotation_during_real_csv_render_denies_old_response(self):
        # Genuine SQLite mutation after checked selection but before the
        # handler's second durable session lookup (no mocked resolver).
        from lightup.finding_export_tenant_checked import render_tenant_findings_csv_checked

        before = self.snapshot()

        def rotate_after_render(*args, **kwargs):
            output = render_tenant_findings_csv_checked(*args, **kwargs)
            self.assertIn(self.fa.finding_id, output)
            with self.store._connect() as con:
                con.execute(
                    "UPDATE sessions SET csrf_token=? WHERE token_hash=?",
                    ("synthetic-rotated-csrf", self.store._token_hash(self.a_token)),
                )
            return output

        with patch(
            "lightup.webapp.finding_exports_unicode_checked.render_tenant_findings_csv_checked",
            side_effect=rotate_after_render,
        ):
            status, headers, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "403 Forbidden")
        self.assertNotIn("text/csv", headers["Content-Type"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn(self.fa.finding_id, body)
        self.assertNotIn("canary-secret", body)
        self.assertEqual(before, self.snapshot())
        _context, live_csrf = self.store.session_context(self.a_token)
        self.assertEqual(live_csrf, "synthetic-rotated-csrf")


if __name__ == "__main__":
    unittest.main()
