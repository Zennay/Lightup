"""Privacy acceptance (expected RED) for opt-in authenticated CSV presentation.

No real cookie/secret/account is used. Source-owner redaction/privacy policy
remains undecided; a sensitive synthetic value must not appear in the output.
"""
from __future__ import annotations

import unittest

import test_finding_export_checked_wsi_optin_20261011_w11 as w11


class CheckedCsvCookiePrivacyW25(unittest.TestCase):
    setUp = w11.CheckedFindingExportWsgiTests.setUp
    tearDown = w11.CheckedFindingExportWsgiTests.tearDown
    request = w11.CheckedFindingExportWsgiTests.request
    snapshot = w11.CheckedFindingExportWsgiTests.snapshot

    def test_known_password_redaction_remains_green_control(self):
        before = self.snapshot()
        status, headers, body = self.request("GET", self.own_url, token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("password=[REDACTED]", body)
        self.assertNotIn("canary-secret", body)
        self.assertEqual(before, self.snapshot())

    def test_synthetic_session_cookie_in_exported_free_text_never_leaks(self):
        canary = "W25SyntheticCookieCanary123456789"
        # Raw imported title/remediation can contain credential-shaped free
        # text. Never use an actual login token or user/client data here.
        payload = "Set-Cookie: lightup_session=" + canary + "; Path=/"
        for column in ("title", "remediation"):
            with self.subTest(column=column):
                with self.store._connect() as con:
                    con.execute(
                        f"UPDATE findings SET {column}=? WHERE finding_id=?",
                        (payload, self.fa.finding_id),
                    )
                before = self.snapshot()
                status, headers, body = self.request(
                    "GET", self.own_url, token=self.a_token
                )
                # Owner may choose generic whole-export rejection or safe
                # redaction; passing through the raw canary is never safe.
                self.assertIn(status, ("200 OK", "400 Bad Request"))
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertNotIn(canary, body)
                self.assertEqual(before, self.snapshot())
                with self.store._connect() as con:
                    con.execute(
                        f"UPDATE findings SET {column}=? WHERE finding_id=?",
                        ("Synthetic innocuous text", self.fa.finding_id),
                    )


if __name__ == "__main__":
    unittest.main()
