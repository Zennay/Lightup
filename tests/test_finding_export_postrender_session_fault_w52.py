"""W52 synthetic WSGI post-render session fault acceptance for opt-in CSV.

Separate tests-only child of W11 #1198, pinned head
bda8381857cc6767e1675e711c48e46b507f6864. No targets, customers,
real ingress, production default source or authorization changes.
"""
from __future__ import annotations

import sqlite3
import unittest
from unittest.mock import patch

from lightup.finding_export_tenant_checked import (
    render_tenant_findings_csv_checked as checked_renderer,
)
import lightup.webapp.finding_exports_unicode_checked as optional_wsi
from tests.test_finding_export_checked_wsi_optin_20261011_w11 import (
    CheckedFindingExportWsgiTests as ExistingFixture,
)


class PostRenderSessionFaultWsgiW52(unittest.TestCase):
    # Adopt only the already-proven disposable SQLite setup/helper, not the
    # 17 inherited tests. Avoid writing to or modifying the original suite.
    setUp = ExistingFixture.setUp
    tearDown = ExistingFixture.tearDown
    request = ExistingFixture.request
    snapshot = ExistingFixture.snapshot

    def _revalidate_with(self, after_render):
        """Swap session result ONLY after the real checked CSV has rendered."""
        before = self.snapshot()
        original_session = self.store.session_context
        marked = [False]
        postrender_checked = [False]

        def guarded_render(*args, **kwargs):
            csv_text = checked_renderer(*args, **kwargs)
            self.assertIn(self.fa.finding_id, csv_text)
            self.assertNotIn("canary-secret", csv_text)
            marked[0] = True
            return csv_text

        def changed_session(token):
            if marked[0]:
                postrender_checked[0] = True
                return after_render(token)
            return original_session(token)

        with patch.object(
            optional_wsi, "render_tenant_findings_csv_checked",
            side_effect=guarded_render,
        ), patch.object(
            self.store, "session_context", side_effect=changed_session
        ):
            status, headers, body = self.request(
                "GET", self.own_url, token=self.a_token
            )

        self.assertTrue(marked[0], "must prove denial was post-render")
        self.assertTrue(postrender_checked[0], "must revalidate after render")
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("text/csv", headers.get("Content-Type", ""))
        self.assertNotIn(self.fa.finding_id, body)
        self.assertNotIn("canary-secret", body)
        self.assertNotIn("private-impact", body)
        self.assertNotIn("local-evidence-canary", body)
        self.assertEqual(before, self.snapshot())

    def test_postrender_database_and_integrity_lookup_failures_are_atomic(self):
        for exception in (
            sqlite3.DatabaseError("synthetic-db-fault"),
            ValueError("synthetic-integrity-fault"),
            KeyError("synthetic-session-fault"),
        ):
            with self.subTest(error=type(exception).__name__):
                def fail(_token):
                    raise exception
                self._revalidate_with(fail)

    def test_postrender_missing_session_refuses_already_rendered_csv(self):
        self._revalidate_with(lambda _token: None)

    def test_postrender_identity_reassignment_refuses_old_tenant_csv(self):
        # Synthetic replacement for a just-changed authorization context,
        # without mutating user records or extending authorization.
        self._revalidate_with(
            lambda _token: (self.store.context_for_user(self.op_user.user_id), "synthetic-csrf")
        )

    def test_postrender_context_type_corruption_refuses_already_rendered_csv(self):
        # The current lookup returns a different object than the originally
        # authenticated AccessContext, even if its repr might look credible.
        self._revalidate_with(
            lambda _token: ("synthetic-not-an-AccessContext", "csrf")
        )


if __name__ == "__main__":
    unittest.main()
