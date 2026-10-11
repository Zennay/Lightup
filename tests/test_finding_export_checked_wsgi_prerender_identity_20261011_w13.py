"""Expected-RED pre-render identity tests for the opt-in checked CSV handler.

Separate from W12 post-render session expiry checks: a direct handler call
with a nonempty but mismatched/revoked token must not read or serialize tenant
findings before comparing that token with the supplied AccessContext.
All data is disposable local SQLite. No target or installed ingress involved.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import test_webapp as base
from lightup.models import Severity
from lightup.webapp.app import AuthState
from lightup.webapp.finding_exports_unicode_checked import create_app_with_checked_exports


class CheckedCsvPrerenderIdentityTests(unittest.TestCase):
    tearDown = base.WebAppTest.tearDown

    def setUp(self):
        base.WebAppTest.setUp(self)
        self.app = create_app_with_checked_exports(self.store)
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Synthetic identity fixture"
        )
        self.finding = self.store.record_finding(
            self.operator, engagement.engagement_id,
            "Local fixture", Severity.LOW, "no-target.invalid",
            "synthetic impact", "synthetic remediation", ("synthetic evidence",),
        )

    def _assert_denied_without_pre_render_read(self, auth, client_id):
        with patch(
            "lightup.webapp.finding_exports_unicode_checked.render_tenant_findings_csv_checked",
            return_value="SYNTHETIC-CSV-MUST-NOT-BE-READ",
        ) as renderer:
            response = self.app.download_findings(auth, {}, client_id)
        self.assertEqual(response.status, "403 Forbidden")
        self.assertNotIn(b"SYNTHETIC-CSV", response.body)
        renderer.assert_not_called()

    def test_forged_operator_context_with_client_session_denied_before_render(self):
        self._assert_denied_without_pre_render_read(
            AuthState(self.operator, None, self.a_token), self.client_b.client_id
        )

    def test_nonexistent_session_denied_before_render(self):
        self._assert_denied_without_pre_render_read(
            AuthState(self.operator, None, "unknown-synthetic-session"),
            self.client_b.client_id,
        )

    def test_revoked_session_denied_before_render(self):
        self.store.revoke_session(self.a_token)
        self._assert_denied_without_pre_render_read(
            AuthState(self.operator, None, self.a_token), self.client_b.client_id
        )

    def test_matching_live_session_still_renders_checked_csv(self):
        live = self.store.session_context(self.a_token)
        self.assertIsNotNone(live)
        response = self.app.download_findings(
            AuthState(live[0], None, self.a_token), {}, self.client_a.client_id
        )
        self.assertEqual(response.status, "200 OK")
        self.assertIn(self.finding.finding_id.encode(), response.body)


if __name__ == "__main__":
    unittest.main()
