"""#1197: post-render persisted-session tuple shape is an admission boundary.

Expected RED on existing W11 opt-in draft for malformed second context lookups.
Actual in-process WSGI, synthetic disposable SQLite, no installed entrypoint.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from lightup.finding_export_tenant_checked import render_tenant_findings_csv_checked
from lightup.webapp import finding_exports_unicode_checked as checked
from test_finding_export_checked_wsi_optin_20261011_w11 import (
    CheckedFindingExportWsgiTests as W11Fixture,
)


class CheckedExportPostrenderSessionShapeW24Tests(unittest.TestCase):
    setUp = W11Fixture.setUp
    tearDown = W11Fixture.tearDown
    request = W11Fixture.request
    snapshot = W11Fixture.snapshot

    def test_canonical_durable_session_can_still_release_redacted_csv(self):
        before = self.snapshot()
        status, headers, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn(self.fa.finding_id, body)
        self.assertNotIn("canary-secret", body)
        self.assertEqual(before, self.snapshot())

    def test_malformed_second_session_lookup_cannot_release_rendered_csv(self):
        live_session = self.store.session_context(self.a_token)
        self.assertIsInstance(live_session, tuple)
        self.assertEqual(len(live_session), 2)
        bad_results = (
            (),
            (live_session[0],),
            (live_session[0], live_session[1], "extra"),
            (None, live_session[1]),
            ("not-an-AccessContext", live_session[1]),
            {"context": live_session[0], "csrf": live_session[1]},
            object(),
        )
        initial_snapshot = self.snapshot()
        original_lookup = self.store.session_context

        for bad in bad_results:
            with self.subTest(result_type=type(bad).__name__, value=repr(bad)):
                after_render = {"value": False}

                def session_lookup(token):
                    if after_render["value"]:
                        return bad
                    return original_lookup(token)

                def render_then_corrupt(*args, **kwargs):
                    output = render_tenant_findings_csv_checked(*args, **kwargs)
                    self.assertIn(self.fa.finding_id, output)
                    after_render["value"] = True
                    return output

                with patch.object(self.store, "session_context", side_effect=session_lookup), patch.object(
                    checked, "render_tenant_findings_csv_checked", side_effect=render_then_corrupt
                ):
                    status, headers, body = self.request(
                        "GET", self.own_url, token=self.a_token
                    )
                self.assertEqual(status, "403 Forbidden")
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertNotIn(self.fa.finding_id, body)
                self.assertNotIn("canary-secret", body)
                self.assertEqual(initial_snapshot, self.snapshot())


if __name__ == "__main__":
    unittest.main()
